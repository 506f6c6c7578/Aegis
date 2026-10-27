import { describe, expect, it } from "vitest";
import { analyzeCache } from "@/domain/audit/cache";
import { maskObserved } from "@/domain/audit/checks";
import { analyzeCookies, parseCookies, parseSetCookie } from "@/domain/audit/cookies";
import { analyzeCsp, extractMetaPolicies, parseContentSecurityPolicies } from "@/domain/audit/csp";
import { analyzeHeaders } from "@/domain/audit/headers";
import type { AuditCheck, HttpEntry, ScanObservations, TlsObservation } from "@/domain/audit/model";
import { analyzeTls } from "@/domain/audit/tls";
import { analyzeHsts, analyzeTransport } from "@/domain/audit/transport";
import { headerMap } from "../support/headers";

const now = Date.UTC(2026, 9, 27);
const dayInMs = 86_400_000;

function find(checks: readonly AuditCheck[], id: string): AuditCheck {
    const check = checks.find((candidate) => candidate.id === id);
    if (!check) throw new Error(`Contrôle ${id} absent`);
    return check;
}

function cspChecks(policy: string) {
    return analyzeCsp(parseContentSecurityPolicies(headerMap({ "content-security-policy": policy })));
}

describe("parseContentSecurityPolicies", () => {
    it("lit les directives, ignore les doublons et sépare les politiques multiples", () => {
        const policies = parseContentSecurityPolicies(headerMap({
            "content-security-policy": ["default-src 'self'; Script-Src 'SELF' https://cdn.aegis-test.fr; script-src *", "object-src 'none', base-uri 'none'"],
            "content-security-policy-report-only": "default-src 'none'"
        }));
        expect(policies).toHaveLength(4);
        expect(policies[0]).toEqual({
            mode: "enforce",
            source: "header",
            directives: [
                { name: "default-src", sources: ["'self'"] },
                { name: "script-src", sources: ["'self'", "https://cdn.aegis-test.fr"] }
            ]
        });
        expect(policies.at(-1)?.mode).toBe("report-only");
    });

    it("préserve la casse des empreintes et masque les nonces et paramètres", () => {
        const [policy] = parseContentSecurityPolicies(headerMap({
            "content-security-policy": "script-src 'SHA256-AbCdEf=' 'nonce-r4nd0m'; report-uri https://rapports.aegis-test.fr/csp?cle=secrete"
        }));
        expect(policy?.directives).toEqual([
            { name: "script-src", sources: ["'sha256-AbCdEf='", "'nonce-…'"] },
            { name: "report-uri", sources: ["https://rapports.aegis-test.fr/csp?…"] }
        ]);
    });
});

describe("CSP en balise meta", () => {
    const astroHead = `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="content-security-policy" content="default-src 'self'; script-src 'self' 'sha256-AbC='; style-src 'self' 'sha256-XyZ='; frame-ancestors 'none'; report-uri https://r.fr/x?k=1"><title>x</title></head><body><meta http-equiv="Content-Security-Policy" content="script-src *"></body></html>`;

    it("extrait uniquement les balises de l'en-tête du document", () => {
        expect(extractMetaPolicies(astroHead)).toHaveLength(1);
        expect(extractMetaPolicies("<meta HTTP-EQUIV='Content-Security-Policy' CONTENT='object-src &#39;none&#39;'>")).toEqual(["object-src 'none'"]);
        expect(extractMetaPolicies("<meta name=\"robots\" content=\"noindex\">")).toEqual([]);
    });

    it("écarte les directives ignorées par les navigateurs et analyse la politique comme appliquée", () => {
        const policies = parseContentSecurityPolicies(headerMap({ "content-security-policy": "frame-ancestors 'none'" }), extractMetaPolicies(astroHead));
        expect(policies.map(({ source }) => source)).toEqual(["header", "meta"]);
        expect(policies[1]?.directives.map(({ name }) => name)).toEqual(["default-src", "script-src", "style-src"]);
        const checks = analyzeCsp(policies);
        expect(find(checks, "csp-present")).toMatchObject({ status: "pass", observed: "en-tête HTTP, balise meta" });
        expect(find(checks, "csp-script-src").status).toBe("pass");
        expect(find(checks, "csp-default-src").status).toBe("pass");
    });

    it("ne retient pas frame-ancestors déclaré en balise meta", () => {
        const policies = parseContentSecurityPolicies(headerMap({}), ["default-src 'self'; frame-ancestors 'none'"]);
        expect(find(analyzeHeaders(headerMap({}), policies), "framing").status).toBe("fail");
    });
});

describe("analyzeCsp", () => {
    it("signale l'absence de CSP comme un problème et ne note pas les directives", () => {
        const checks = analyzeCsp([]);
        expect(find(checks, "csp-present").status).toBe("fail");
        expect(checks.filter(({ status }) => status === "not-applicable")).toHaveLength(checks.length - 1);
    });

    it("distingue une politique Report-Only", () => {
        const checks = analyzeCsp(parseContentSecurityPolicies(headerMap({ "content-security-policy-report-only": "default-src 'self'" })));
        expect(find(checks, "csp-present").status).toBe("warning");
    });

    it("valide une politique stricte", () => {
        const checks = cspChecks("default-src 'self'; script-src 'self' 'sha256-abc='; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
        expect(checks.every(({ status }) => status === "pass")).toBe(true);
    });

    it("signale unsafe-inline sans empreinte et unsafe-eval", () => {
        expect(find(cspChecks("script-src 'self' 'unsafe-inline'"), "csp-script-src").status).toBe("fail");
        expect(find(cspChecks("script-src 'self' 'unsafe-inline' 'nonce-abc'"), "csp-script-src").status).toBe("pass");
        expect(find(cspChecks("script-src 'self' 'unsafe-eval'"), "csp-script-src").status).toBe("warning");
    });

    it("signale les sources trop larges et l'absence de repli", () => {
        expect(find(cspChecks("script-src https:"), "csp-script-src").status).toBe("fail");
        expect(find(cspChecks("default-src *"), "csp-default-src").status).toBe("fail");
        expect(find(cspChecks("script-src 'self'"), "csp-default-src").status).toBe("warning");
        expect(find(cspChecks("default-src 'self'; img-src *"), "csp-broad-sources").status).toBe("warning");
        expect(find(cspChecks("default-src 'self'; style-src 'self' 'unsafe-inline'"), "csp-style-src").status).toBe("warning");
    });

    it("utilise default-src comme repli de script-src et object-src, mais pas de base-uri ni form-action", () => {
        const checks = cspChecks("default-src 'none'");
        expect(find(checks, "csp-script-src").status).toBe("pass");
        expect(find(checks, "csp-object-src").status).toBe("pass");
        expect(find(checks, "csp-base-uri").status).toBe("warning");
        expect(find(checks, "csp-form-action").status).toBe("warning");
    });

    it("retient la politique la plus stricte quand plusieurs politiques s'appliquent", () => {
        const checks = analyzeCsp(parseContentSecurityPolicies(headerMap({ "content-security-policy": ["script-src * 'unsafe-inline'", "script-src 'self'"] })));
        expect(find(checks, "csp-script-src").status).toBe("pass");
    });
});

describe("analyzeHeaders", () => {
    it("valide une configuration complète", () => {
        const headers = headerMap({
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "camera=()",
            "cross-origin-opener-policy": "same-origin",
            "cross-origin-resource-policy": "same-origin",
            "cross-origin-embedder-policy": "require-corp",
            "content-security-policy": "frame-ancestors 'none'"
        });
        const checks = analyzeHeaders(headers, parseContentSecurityPolicies(headers));
        expect(checks.map(({ status }) => status)).toEqual(Array(checks.length).fill("pass"));
    });

    it("signale les en-têtes absents ou dangereux", () => {
        const checks = analyzeHeaders(headerMap({ "referrer-policy": "unsafe-url" }), []);
        expect(find(checks, "x-content-type-options").status).toBe("warning");
        expect(find(checks, "referrer-policy").status).toBe("fail");
        expect(find(checks, "framing").status).toBe("fail");
        expect(find(checks, "cross-origin-embedder-policy").status).toBe("not-applicable");
    });

    it("accepte X-Frame-Options pour compatibilité et refuse ALLOW-FROM", () => {
        expect(find(analyzeHeaders(headerMap({ "x-frame-options": "DENY" }), []), "framing").status).toBe("pass");
        expect(find(analyzeHeaders(headerMap({ "x-frame-options": "ALLOW-FROM https://a.fr" }), []), "framing").status).toBe("fail");
        const permissive = headerMap({ "content-security-policy": "frame-ancestors *" });
        expect(find(analyzeHeaders(permissive, parseContentSecurityPolicies(permissive)), "framing").status).toBe("fail");
    });

    it("retient la dernière valeur valide de Referrer-Policy", () => {
        expect(find(analyzeHeaders(headerMap({ "referrer-policy": "unsafe-url, inconnue, no-referrer" }), []), "referrer-policy").status).toBe("pass");
    });
});

describe("cookies", () => {
    it("ne conserve jamais la valeur d'un cookie", () => {
        const cookie = parseSetCookie("session=valeur-tres-secrete; Path=/; Secure; HttpOnly; SameSite=Strict", now);
        expect(JSON.stringify(cookie)).not.toContain("valeur-tres-secrete");
        expect(cookie).toEqual({
            name: "session",
            secure: true,
            httpOnly: true,
            sameSite: "Strict",
            domain: null,
            path: "/",
            lifetime: { kind: "session" },
            sensitive: true,
            prefix: null
        });
    });

    it("ne prend pas une valeur pour un nom quand le signe égal manque", () => {
        expect(parseSetCookie("jetonsecret; Secure", now)?.name).toBe("");
    });

    it("lit Domain, Max-Age, Expires et les préfixes", () => {
        expect(parseSetCookie("__Host-id=x; Max-Age=3600; Secure; Path=/", now)).toMatchObject({ prefix: "__Host-", lifetime: { kind: "persistent", seconds: 3600 } });
        expect(parseSetCookie("a=b; Domain=.Aegis-Test.fr; Expires=Wed, 27 Oct 2027 00:00:00 GMT", now)).toMatchObject({ domain: "aegis-test.fr", lifetime: { kind: "persistent" } });
        expect(parseSetCookie("a=b; samesite=none", now)?.sameSite).toBe("None");
        expect(parseSetCookie("a=b; SameSite=invalide", now)?.sameSite).toBeNull();
    });

    it("ignore les cookies de suppression", () => {
        expect(parseSetCookie("a=; Max-Age=0", now)).toBeNull();
        expect(parseSetCookie("a=; Expires=Thu, 01 Jan 1970 00:00:00 GMT", now)).toBeNull();
    });

    it("déduplique et borne le nombre de cookies", () => {
        const headers = headerMap({ "set-cookie": [...Array.from({ length: 80 }, (_, index) => `c${index}=x`), "c1=y; Secure"] });
        expect(parseCookies(headers, now)).toHaveLength(50);
    });

    it("signale les cookies sensibles sans protection", () => {
        const checks = analyzeCookies(parseCookies(headerMap({ "set-cookie": ["sessionid=x; Path=/", "theme=sombre; Secure; SameSite=Lax"] }), now));
        expect(find(checks, "cookies-secure")).toMatchObject({ status: "fail", priority: "high", observed: "sessionid" });
        expect(find(checks, "cookies-httponly").status).toBe("fail");
        expect(find(checks, "cookies-samesite").status).toBe("warning");
    });

    it("n'exige pas HttpOnly pour un jeton CSRF lisible par la page", () => {
        const checks = analyzeCookies(parseCookies(headerMap({ "set-cookie": "csrftoken=x; Secure; SameSite=Strict" }), now));
        expect(find(checks, "cookies-httponly").status).toBe("not-applicable");
    });

    it("rend les contrôles non applicables sans cookie", () => {
        expect(analyzeCookies([]).every(({ status }) => status === "not-applicable")).toBe(true);
    });
});

describe("analyzeCache", () => {
    it("exige un cache privé quand des cookies sensibles sont déposés", () => {
        const cookies = parseCookies(headerMap({ "set-cookie": "session=x; Secure; HttpOnly" }), now);
        expect(analyzeCache(headerMap({ "cache-control": "public, max-age=600" }), cookies)[0]?.status).toBe("fail");
        expect(analyzeCache(headerMap({}), cookies)[0]?.status).toBe("warning");
        expect(analyzeCache(headerMap({ "cache-control": "private, no-store" }), cookies)[0]?.status).toBe("pass");
    });

    it("signale les versions logicielles exposées sans les traiter comme critiques", () => {
        const [, disclosure] = analyzeCache(headerMap({ "server": "Apache/2.4.1", "x-powered-by": "PHP/8.1" }), []);
        expect(disclosure).toMatchObject({ status: "warning", priority: "low" });
        expect(analyzeCache(headerMap({ server: "nginx" }), [])[1]?.status).toBe("pass");
    });
});

const established: TlsObservation = {
    status: "established",
    protocol: "TLSv1.3",
    cipher: "TLS_AES_256_GCM_SHA384",
    certificate: { subject: "aegis-test.fr", issuer: "Aegis Test CA", validFrom: now - 10 * dayInMs, validTo: now + 60 * dayInMs, subjectAltNames: ["aegis-test.fr"], key: "ECDSA P-256", fingerprint: "AA" },
    chain: []
};

function observations(overrides: Partial<ScanObservations>): ScanObservations {
    return {
        domain: "aegis-test.fr",
        tls: established,
        chain: { hops: [{ url: "https://aegis-test.fr/", status: 200, method: "HEAD", location: null }], outcome: "completed", refusedDestination: null },
        final: { url: "https://aegis-test.fr/", status: 200, method: "HEAD", headers: headerMap({ "strict-transport-security": "max-age=63072000; includeSubDomains" }) },
        httpEntry: { available: true, status: 301, target: "https-same-host", location: "https://aegis-test.fr/" },
        metaPolicies: [],
        ...overrides
    };
}

describe("analyzeTransport", () => {
    it("valide un site correctement servi en HTTPS", () => {
        expect(analyzeTransport(observations({}), now).map(({ status }) => status)).toEqual(Array(7).fill("pass"));
    });

    it.each<[TlsObservation, Record<string, string>]>([
        [{ status: "failed", reason: "expired" }, { "certificate-chain": "fail", "certificate-hostname": "not-applicable", "certificate-expiry": "fail" }],
        [{ status: "failed", reason: "hostname-mismatch" }, { "certificate-chain": "pass", "certificate-hostname": "fail" }],
        [{ status: "failed", reason: "self-signed" }, { "certificate-chain": "fail" }],
        [{ status: "failed", reason: "connection-refused" }, { "https-available": "fail", "certificate-chain": "not-applicable" }]
    ])("interprète l'échec TLS %#", (tls, expected) => {
        const checks = analyzeTransport(observations({ tls, final: null }), now);
        for (const [id, status] of Object.entries(expected)) expect(find(checks, id).status).toBe(status);
    });

    it("prévient de l'expiration prochaine du certificat", () => {
        const soon = (days: number): TlsObservation => ({ ...established, certificate: { ...established.certificate, validTo: now + days * dayInMs } });
        expect(find(analyzeTransport(observations({ tls: soon(20) }), now), "certificate-expiry").status).toBe("warning");
        expect(find(analyzeTransport(observations({ tls: soon(5) }), now), "certificate-expiry").status).toBe("fail");
    });

    it.each<[HttpEntry, string]>([
        [{ available: true, status: 308, target: "https-same-host", location: null }, "pass"],
        [{ available: true, status: 302, target: "https-same-host", location: null }, "warning"],
        [{ available: true, status: 301, target: "https-other-host", location: null }, "warning"],
        [{ available: true, status: 200, target: "none", location: null }, "fail"],
        [{ available: true, status: 301, target: "http", location: null }, "fail"],
        [{ available: false }, "not-applicable"]
    ])("évalue l'entrée HTTP %#", (httpEntry, status) => {
        expect(find(analyzeTransport(observations({ httpEntry }), now), "http-redirect").status).toBe(status);
    });

    it.each([
        ["insecure-redirect", "fail"],
        ["loop", "fail"],
        ["too-many-redirects", "fail"],
        ["ip-literal", "fail"],
        ["out-of-scope", "warning"]
    ] as const)("évalue l'issue de redirection %s", (outcome, status) => {
        const checks = analyzeTransport(observations({ chain: { hops: [], outcome, refusedDestination: null } }), now);
        expect(find(checks, "redirect-chain").status).toBe(status);
    });

    it.each([
        ["max-age=63072000; includeSubDomains; preload", "pass"],
        ["max-age=15552000", "pass"],
        ["max-age=3600", "warning"],
        ["max-age=0", "fail"],
        ["includeSubDomains", "fail"],
        ["max-age=abc", "fail"]
    ])("évalue HSTS %s", (value, status) => {
        expect(analyzeHsts(headerMap({ "strict-transport-security": value })).status).toBe(status);
    });
});

describe("analyzeTls", () => {
    it.each([
        ["TLSv1.3", "TLS_AES_128_GCM_SHA256", "pass", "pass"],
        ["TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "warning", "pass"],
        ["TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "warning", "warning"],
        ["TLSv1.2", "TLS_RSA_WITH_AES_128_GCM_SHA256", "warning", "fail"]
    ])("évalue %s avec %s", (protocol, cipher, protocolStatus, cipherStatus) => {
        const [protocolCheck, cipherCheck] = analyzeTls({ ...established, protocol, cipher });
        expect(protocolCheck?.status).toBe(protocolStatus);
        expect(cipherCheck?.status).toBe(cipherStatus);
    });

    it("signale l'échec de négociation sans tester de version obsolète", () => {
        expect(analyzeTls({ status: "failed", reason: "handshake-failed" })[0]?.status).toBe("fail");
    });
});

describe("maskObserved", () => {
    it("masque les paramètres d'URL, retire les caractères de contrôle et tronque", () => {
        expect(maskObserved("report-uri https://a.fr/r?token=secret")).toBe("report-uri https://a.fr/r?…");
        expect(maskObserved("valeur\u0000\u001b[31m")).toBe("valeur  [31m");
        expect(maskObserved("x".repeat(1000))).toHaveLength(601);
    });
});
