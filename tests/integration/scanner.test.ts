import { afterEach, describe, expect, it } from "vitest";
import { buildReport } from "@/domain/audit/report";
import type { ScanObservations } from "@/domain/audit/model";
import { runScan } from "@/services/scanner/scan";
import {
    createFakeResolver,
    createScanContext,
    type Handler,
    publicAddress,
    respond,
    secureHeaders,
    startTarget,
    type Target,
    testDomain
} from "../support/target";

const targets: Target[] = [];

afterEach(async () => {
    await Promise.all(targets.splice(0).map((target) => target.close()));
});

async function scan(options: Parameters<typeof startTarget>[0] = {}, records: Parameters<typeof createFakeResolver>[0] = { [testDomain]: [publicAddress] }, domain = testDomain, timeoutMs?: number) {
    const target = await startTarget(options);
    targets.push(target);
    const resolver = createFakeResolver(records);
    const observations = await runScan(domain, createScanContext(target, resolver, timeoutMs));
    return { observations, target, resolver };
}

function report(observations: ScanObservations) {
    return buildReport({ id: "rapport", displayDomain: observations.domain, observations, startedAt: 0, completedAt: Date.now(), expiresAt: Date.now() + 60_000 });
}

const routes = (table: Record<string, Handler>): Handler => (request, response) => {
    const handler = table[`${request.headers.host}${request.url}`] ?? respond(404);
    handler(request, response);
};

describe("scan d'un domaine valide", () => {
    it("analyse TLS, en-têtes, cookies et redirection HTTP sans lire de valeur de cookie", async () => {
        const { observations, target } = await scan({
            https: respond(200, { ...secureHeaders, "Set-Cookie": ["__Host-session=valeur-secrete-123; Path=/; Secure; HttpOnly; SameSite=Strict"] })
        });
        expect(observations.tls).toMatchObject({ status: "established", certificate: { subject: testDomain, issuer: "Aegis Tests (Aegis Test CA)" } });
        expect(observations.final).toMatchObject({ status: 200, method: "HEAD", url: `https://${testDomain}/` });
        expect(observations.httpEntry).toEqual({ available: true, status: 301, target: "https-same-host", location: `https://${testDomain}/` });
        expect(new Set(target.contacted)).toEqual(new Set([`${publicAddress}:443`, `${publicAddress}:80`]));

        const result = report(observations);
        expect(result.summary.fail).toBe(0);
        expect(result.score.value).toBeGreaterThanOrEqual(95);
        expect(result.cookies).toEqual([expect.objectContaining({ name: "__Host-session", httpOnly: true, secure: true })]);
        expect(JSON.stringify(result)).not.toContain("valeur-secrete-123");
    });

    it("se replie sur GET quand HEAD est refusé, sans lire le corps", async () => {
        const methods: string[] = [];
        const { observations } = await scan({
            https: (request, response) => {
                methods.push(request.method ?? "");
                if (request.method === "HEAD") response.writeHead(405).end();
                else response.writeHead(200, secureHeaders).end("x".repeat(5_000_000));
            }
        });
        expect(methods).toEqual(["HEAD", "GET"]);
        expect(observations.final).toMatchObject({ status: 200, method: "GET" });
    });

    it("considère le port 80 fermé comme une absence de version HTTP", async () => {
        const { observations } = await scan({ http: null });
        expect(observations.httpEntry).toEqual({ available: false });
    });

    it("signale un site servi en HTTP sans redirection", async () => {
        const { observations } = await scan({ http: respond(200) });
        expect(observations.httpEntry).toMatchObject({ available: true, status: 200, target: "none" });
    });
});

describe("CSP en balise meta", () => {
    const page = `<!doctype html><html><head><meta http-equiv="content-security-policy" content="default-src 'self'; script-src 'self' 'sha256-abc='; object-src 'none'; base-uri 'self'; form-action 'self'"></head><body>${"x".repeat(200_000)}</body></html>`;

    it("lit la CSP de l'en-tête HTML sans télécharger le reste de la page", async () => {
        const bodies: number[] = [];
        const { observations } = await scan({
            https: (request, response) => {
                response.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "X-Content-Type-Options": "nosniff" });
                if (request.method === "GET") response.write(page.slice(0, 60_000), () => bodies.push(60_000));
                response.end(request.method === "GET" ? page.slice(60_000) : undefined);
            },
            http: null
        });
        expect(observations.metaPolicies).toHaveLength(1);
        const result = report(observations);
        expect(result.csp).toEqual([expect.objectContaining({ source: "meta", mode: "enforce" })]);
        expect(result.checks.find(({ id }) => id === "csp-script-src")?.status).toBe("pass");
    });

    it("ignore un document compressé ou qui n'est pas du HTML", async () => {
        const { observations } = await scan({ https: respond(200, { "Content-Type": "text/html", "Content-Encoding": "gzip" }), http: null });
        expect(observations.final?.status).toBe(200);
        expect(observations.metaPolicies).toEqual([]);
        const json = await scan({ https: respond(200, { "Content-Type": "application/json" }), http: null });
        expect(json.observations.metaPolicies).toEqual([]);
    });
});

describe("redirections", () => {
    it("suit une redirection vers un sous-domaine du domaine vérifié", async () => {
        const { observations, resolver } = await scan(
            { https: routes({ [`${testDomain}/`]: respond(301, { Location: `https://www.${testDomain}/` }), [`www.${testDomain}/`]: respond(200, secureHeaders) }) },
            { [testDomain]: [publicAddress], [`www.${testDomain}`]: ["93.184.215.20"] }
        );
        expect(observations.chain.outcome).toBe("completed");
        expect(observations.chain.hops.map(({ status, url }) => `${status} ${url}`)).toEqual([`301 https://${testDomain}/`, `200 https://www.${testDomain}/`]);
        expect(resolver.lookups.filter((hostname) => hostname === testDomain)).toHaveLength(1);
    });

    it.each([
        ["http://127.0.0.1/", "ip-literal"],
        ["https://169.254.169.254/latest/meta-data/", "ip-literal"],
        ["https://[::1]/", "ip-literal"],
        ["https://localhost/", "invalid-host"],
        ["https://metadata.google.internal/", "invalid-host"],
        ["https://autre-domaine.fr/", "out-of-scope"],
        [`http://${testDomain}/`, "insecure-redirect"],
        [`https://${testDomain}:8443/`, "port"],
        [`https://admin:secret@${testDomain}/`, "credentials"],
        ["file:///etc/passwd", "unsupported-scheme"]
    ])("refuse la redirection vers %s (%s) sans la contacter", async (location, outcome) => {
        const { observations, target } = await scan({ https: respond(302, { Location: location }), http: null });
        expect(observations.chain.outcome).toBe(outcome);
        expect(observations.chain.hops).toHaveLength(1);
        expect(target.contacted.every((address) => address.startsWith(`${publicAddress}:`))).toBe(true);
    });

    it("détecte une boucle", async () => {
        const { observations } = await scan({ https: routes({ [`${testDomain}/`]: respond(301, { Location: "/a" }), [`${testDomain}/a`]: respond(301, { Location: "/" }) }) });
        expect(observations.chain.outcome).toBe("loop");
    });

    it("ne suit jamais plus de cinq redirections", async () => {
        const requested: string[] = [];
        const { observations } = await scan({
            https: (request, response) => {
                requested.push(request.url ?? "");
                response.writeHead(301, { Location: `/etape-${requested.length}` }).end();
            },
            http: null
        });
        expect(observations.chain.outcome).toBe("too-many-redirects");
        expect(observations.chain.hops).toHaveLength(6);
        expect(new Set(requested).size).toBe(6);
    });

    it("signale une redirection sans destination", async () => {
        const { observations } = await scan({ https: respond(301) });
        expect(observations.chain.outcome).toBe("missing-location");
    });

    it("masque les paramètres des destinations dans le rapport", async () => {
        const { observations } = await scan(
            { https: routes({ [`${testDomain}/`]: respond(302, { Location: "/connexion?jeton=secret" }), [`${testDomain}/connexion?jeton=secret`]: respond(200) }) }
        );
        expect(JSON.stringify(observations.chain)).not.toContain("secret");
        expect(observations.chain.hops.at(-1)?.url).toBe(`https://${testDomain}/connexion?…`);
    });
});

describe("protection contre le rebinding DNS", () => {
    it("refuse un domaine dont une adresse résolue est interne", async () => {
        const target = await startTarget();
        targets.push(target);
        const resolver = createFakeResolver({ [testDomain]: [publicAddress, "10.0.0.8"] });
        await expect(runScan(testDomain, createScanContext(target, resolver))).rejects.toMatchObject({ code: "forbidden-address" });
        expect(target.contacted).toEqual([]);
    });

    it("garde l'adresse épinglée même si le résolveur change de réponse", async () => {
        const answers = [[publicAddress], ["127.0.0.1"], ["169.254.169.254"]];
        const { target, resolver } = await scan({}, { [testDomain]: () => answers.shift() ?? ["127.0.0.1"] });
        expect(resolver.lookups).toEqual([testDomain]);
        expect(target.contacted.every((address) => address.startsWith(`${publicAddress}:`))).toBe(true);
    });

    it("refuse un sous-domaine de redirection qui résout vers une adresse interne", async () => {
        const { observations, target } = await scan(
            { https: routes({ [`${testDomain}/`]: respond(301, { Location: `https://interne.${testDomain}/` }) }) },
            { [testDomain]: [publicAddress], [`interne.${testDomain}`]: ["192.168.1.10"] }
        );
        expect(observations.chain.outcome).toBe("invalid-host");
        expect(target.contacted.some((address) => address.startsWith("192.168."))).toBe(false);
    });
});

describe("erreurs TLS", () => {
    it.each([
        ["expired", testDomain, "expired"],
        ["self-signed", testDomain, "self-signed"],
        ["valid", "autre-domaine.fr", "hostname-mismatch"]
    ] as const)("ne contourne jamais un certificat %s", async (certificate, domain, reason) => {
        const { observations } = await scan({ certificate, http: null }, { [domain]: [publicAddress] }, domain);
        expect(observations.tls).toEqual({ status: "failed", reason });
        expect(observations.final).toBeNull();
        const result = report(observations);
        expect(result.checks.find(({ id }) => id === "https-available")?.status).toBe("fail");
        expect(result.score.categories.filter(({ evaluated }) => evaluated).map(({ id }) => id)).toEqual(["transport"]);
    });
});

describe("réponses HTTP anormales", () => {
    it("rejette une réponse qui n'est pas du HTTP", async () => {
        const { observations } = await scan({ rawTls: (socket) => socket.end("ceci n'est pas une réponse HTTP\r\n\r\n"), http: null });
        expect(observations.tls.status).toBe("established");
        expect(observations.final).toBeNull();
        expect(observations.chain.outcome).toBe("request-failed");
    });

    it("rejette des en-têtes trop volumineux", async () => {
        const { observations } = await scan({ https: respond(200, { "X-Remplissage": "a".repeat(40_000) }), http: null });
        expect(observations.final).toBeNull();
    });

    it("abandonne un serveur qui ne répond pas dans le délai", async () => {
        const startedAt = Date.now();
        const { observations } = await scan({ https: () => undefined, http: null }, undefined, testDomain, 400);
        expect(observations.final).toBeNull();
        expect(Date.now() - startedAt).toBeLessThan(3_000);
    });
});
