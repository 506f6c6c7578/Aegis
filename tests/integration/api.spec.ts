import { type APIRequestContext, type APIResponse, expect, test } from "@playwright/test";

const robots = "noindex, nofollow, noarchive, nosnippet";
const origin = "http://localhost:4322";
const jsonHeaders = { "Origin": origin, "Content-Type": "application/json" };
const unknownId = "A".repeat(43);

test.describe.configure({ mode: "serial" });

async function expectJsonError(response: APIResponse, status: number, code?: string) {
    expect(response.status()).toBe(status);
    expect(response.headers()["cache-control"]).toBe("no-store");
    const body: unknown = await response.json();
    expect(body).toEqual(code ? { error: expect.any(String), code } : { error: expect.any(String) });
    expect(JSON.stringify(body)).not.toMatch(/\bat \S+:\d+|\.mjs|\bstack\b|node:internal|Error:/);
}

function postChallenge(request: APIRequestContext, domain: unknown, headers: Record<string, string> = jsonHeaders) {
    return request.post("/api/verification/challenge", { headers, data: JSON.stringify({ domain }) });
}

function readCookies(response: APIResponse): string[] {
    return response.headersArray().filter(({ name }) => name.toLowerCase() === "set-cookie").map(({ value }) => value);
}

test.describe("POST /api/verification/challenge", () => {
    test("crée un challenge normalisé et des cookies durcis sans exposer le jeton", async ({ request }) => {
        const response = await postChallenge(request, "  Bücher.PaulViandier.com. ");
        expect(response.status()).toBe(201);
        expect(response.headers()["cache-control"]).toBe("no-store");
        expect(response.headers()["x-content-type-options"]).toBe("nosniff");
        expect(response.headers()["x-robots-tag"]).toBe(robots);

        const { challenge } = await response.json();
        expect(challenge).toMatchObject({
            domain: "xn--bcher-kva.paulviandier.com",
            displayDomain: "bücher.paulviandier.com",
            recordName: "_aegis-verify.xn--bcher-kva.paulviandier.com",
            recordValue: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/)
        });

        const cookies = readCookies(response);
        for (const name of ["__Host-aegis-session", "__Host-aegis-challenge"]) {
            const cookie = cookies.find((value) => value.startsWith(`${name}=`));
            expect(cookie).toBeDefined();
            expect(cookie).toMatch(/; Path=\//);
            expect(cookie).toMatch(/; HttpOnly/);
            expect(cookie).toMatch(/; Secure/);
            expect(cookie).toMatch(/; SameSite=Strict/);
            expect(cookie).not.toMatch(/Domain=/i);
        }
        const challengeCookie = cookies.find((value) => value.startsWith("__Host-aegis-challenge=")) ?? "";
        const payload = Buffer.from(challengeCookie.split("=")[1]?.split(".")[0] ?? "", "base64url").toString();
        expect(payload).not.toContain(challenge.recordValue);
    });

    for (const [domain, code] of [
        ["https://paulviandier.com", "url"],
        ["paulviandier.com/admin", "path"],
        ["paulviandier.com:8443", "port"],
        ["admin:secret@paulviandier.com", "credentials"],
        ["*.paulviandier.com", "wildcard"],
        ["127.0.0.1", "ip-address"],
        ["[::1]", "ip-address"],
        ["localhost", "single-label"],
        ["metadata.google.internal", "special-use"],
        ["co.uk", "public-suffix"]
    ] as const) {
        test(`refuse ${domain}`, async ({ request }) => {
            await expectJsonError(await postChallenge(request, domain), 422, code);
        });
    }

    test("refuse un corps invalide, trop long ou avec des champs inconnus", async ({ request }) => {
        await expectJsonError(await postChallenge(request, 42), 400);
        await expectJsonError(await postChallenge(request, "a".repeat(300)), 400);
        await expectJsonError(await request.post("/api/verification/challenge", { headers: jsonHeaders, data: "{pas du json" }), 400);
        await expectJsonError(await request.post("/api/verification/challenge", { headers: jsonHeaders, data: JSON.stringify({ domain: "paulviandier.com", url: "http://10.0.0.1" }) }), 400);
        const large = await request.post("/api/verification/challenge", { headers: jsonHeaders, data: JSON.stringify({ domain: "a", padding: "x".repeat(4_000) }) });
        expect([400, 413]).toContain(large.status());
    });

    test("refuse les requêtes intersites ou sans origine", async ({ request }) => {
        await expectJsonError(await postChallenge(request, "paulviandier.com", { "Content-Type": "application/json" }), 403);
        await expectJsonError(await postChallenge(request, "paulviandier.com", { ...jsonHeaders, Origin: "https://evil.example" }), 403);
        await expectJsonError(await postChallenge(request, "paulviandier.com", { ...jsonHeaders, "Sec-Fetch-Site": "cross-site" }), 403);
        const form = await request.post("/api/verification/challenge", { headers: { "Origin": "https://evil.example", "Content-Type": "application/x-www-form-urlencoded" }, data: "domain=a.fr" });
        expect(form.status()).toBe(403);
        await expectJsonError(await postChallenge(request, "paulviandier.com", { Origin: origin, "Content-Type": "text/plain" }), 415);
    });
});

test.describe("POST /api/verification/confirm", () => {
    test("refuse une confirmation sans challenge actif", async ({ playwright }) => {
        const context = await playwright.request.newContext({ baseURL: origin });
        await expectJsonError(await context.post("/api/verification/confirm", { headers: jsonHeaders, data: "{}" }), 409, "challenge-missing");
        await context.dispose();
    });

    test("reste en attente tant que le TXT n'est pas lisible et impose un délai", async ({ request }) => {
        expect((await postChallenge(request, "paulviandier.com")).status()).toBe(201);
        const first = await request.post("/api/verification/confirm", { headers: jsonHeaders, data: "{}" });
        expect(first.status()).toBe(200);
        expect(await first.json()).toMatchObject({ status: "pending", reason: expect.stringMatching(/^(?:not-found|dns-error)$/), attemptsRemaining: 9 });
        expect(readCookies(first).some((cookie) => cookie.startsWith("__Host-aegis-proof=") && !cookie.includes("deleted"))).toBe(false);

        const second = await request.post("/api/verification/confirm", { headers: jsonHeaders, data: "{}" });
        await expectJsonError(second, 429, "rate-limited");
        expect(Number(second.headers()["retry-after"])).toBeGreaterThan(0);
    });
});

test.describe("analyses et rapports", () => {
    test("refuse une analyse sans preuve de propriété", async ({ request }) => {
        await expectJsonError(await request.post("/api/audits", { headers: jsonHeaders, data: JSON.stringify({ domain: "paulviandier.com" }) }), 403, "unauthorized");
        await postChallenge(request, "paulviandier.com");
        await expectJsonError(await request.post("/api/audits", { headers: jsonHeaders, data: JSON.stringify({ domain: "paulviandier.com" }) }), 403, "unauthorized");
        const forged = await request.post("/api/audits", {
            headers: { ...jsonHeaders, Cookie: "__Host-aegis-proof=eyJkb21haW4iOiJwYXVsdmlhbmRpZXIuY29tIn0.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
            data: JSON.stringify({ domain: "paulviandier.com" })
        });
        await expectJsonError(forged, 403, "unauthorized");
    });

    test("ne révèle aucun rapport inconnu ou d'une autre session", async ({ request }) => {
        await expectJsonError(await request.get(`/api/audits/${unknownId}`), 404);
        await expectJsonError(await request.get("/api/audits/..%2F..%2Fetc"), 404);
        await expectJsonError(await request.get("/api/audits/court"), 404);
    });

    test("la page de rapport n'est jamais mise en cache et refuse les identifiants invalides", async ({ request }) => {
        const page = await request.get(`/rapport/${unknownId}`);
        expect(page.status()).toBe(200);
        expect(page.headers()["cache-control"]).toBe("no-store");
        expect(page.headers()["x-robots-tag"]).toBe(robots);
        expect((await request.get("/rapport/identifiant-invalide")).status()).toBe(404);
    });
});

test.describe("méthodes HTTP", () => {
    for (const [method, path, allow] of [
        ["GET", "/api/verification/challenge", "POST"],
        ["PUT", "/api/verification/confirm", "POST"],
        ["DELETE", "/api/audits", "POST"],
        ["POST", `/api/audits/${unknownId}`, "GET"],
        ["PATCH", `/api/audits/${unknownId}`, "GET"]
    ] as const) {
        test(`refuse ${method} ${path}`, async ({ request }) => {
            const response = await request.fetch(path, { method, headers: jsonHeaders, data: method === "GET" ? undefined : "{}" });
            expect([403, 405]).toContain(response.status());
            if (response.status() === 405) expect(response.headers()["allow"]).toBe(allow);
        });
    }
});

test.describe("pages HTML", () => {
    for (const path of ["/", "/verifier", "/mentions-legales", "/confidentialite", `/rapport/${unknownId}`]) {
        test(`${path} n'est pas indexable et porte une CSP stricte`, async ({ request }) => {
            const response = await request.get(path);
            expect(response.status()).toBe(200);
            const html = await response.text();
            expect(html).toContain(`<meta name="robots" content="${robots}">`);
            const policy = html.match(/<meta http-equiv="content-security-policy" content="([^"]*)"/i)?.[1] ?? response.headers()["content-security-policy"];
            expect(policy).toContain("default-src 'self'");
            expect(policy).toMatch(/script-src 'self'/);
            expect(policy).not.toContain("unsafe-inline");
            expect(policy).not.toContain("unsafe-eval");
            expect(html).not.toContain('rel="canonical"');
            expect(html).not.toMatch(/sitemap/i);
            expect(html).not.toMatch(/style="/);
            expect(html).not.toMatch(/<script[^>]+src="https?:/);
            expect(html).not.toMatch(/https:\/\/fonts\.(?:googleapis|gstatic)/);
        });
    }

    test("les pages interactives s'affichent d'abord en skeleton", async ({ request }) => {
        const verification = await (await request.get("/verifier")).text();
        expect(verification).toContain('aria-label="Chargement de la vérification"');
        expect(verification).not.toContain("Quel domaine veux-tu analyser");
        expect(await (await request.get(`/rapport/${unknownId}`)).text()).toContain('aria-label="Chargement du rapport"');
    });

    test("aucun sitemap n'est publié", async ({ request }) => {
        expect((await request.get("/sitemap-index.xml")).status()).toBe(404);
        expect((await request.get("/sitemap-0.xml")).status()).toBe(404);
    });

    test("les réponses dynamiques portent les en-têtes de sécurité", async ({ request }) => {
        const headers = (await request.get(`/rapport/${unknownId}`)).headers();
        expect(headers["content-security-policy"]).toContain("frame-ancestors 'none'");
        expect(headers["x-frame-options"]).toBe("DENY");
        expect(headers["referrer-policy"]).toBe("strict-origin-when-cross-origin");
        expect(headers["cross-origin-opener-policy"]).toBe("same-origin");
        expect(headers["permissions-policy"]).toContain("camera=()");
        expect(headers["strict-transport-security"]).toContain("max-age=");
        expect(headers["x-powered-by"]).toBeUndefined();
    });
});

test.describe("limitation de débit", () => {
    test("limite la création de challenges par session et par adresse", async ({ request }) => {
        let limited: APIResponse | null = null;
        for (let attempt = 0; attempt < 12 && !limited; attempt += 1) {
            const response = await postChallenge(request, "paulviandier.com");
            if (response.status() === 429) limited = response;
            else expect(response.status()).toBe(201);
        }
        expect(limited).not.toBeNull();
        if (limited) {
            await expectJsonError(limited, 429, "rate-limited");
            expect(Number(limited.headers()["retry-after"])).toBeGreaterThan(0);
        }
    });
});
