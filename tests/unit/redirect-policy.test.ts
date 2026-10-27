import { describe, expect, it } from "vitest";
import { formatDisplayUrl } from "@/lib/network/display";
import { evaluateRedirect, type RedirectRefusal } from "@/lib/network/redirect-policy";

const current = new URL("https://aegis-test.fr/");
const scope = "aegis-test.fr";

describe("evaluateRedirect", () => {
    it.each([
        ["/fr/", "https://aegis-test.fr/fr/"],
        ["https://www.aegis-test.fr/", "https://www.aegis-test.fr/"],
        ["https://WWW.Aegis-Test.FR/accueil", "https://www.aegis-test.fr/accueil"],
        ["https://aegis-test.fr:443/", "https://aegis-test.fr/"],
        ["http://aegis-test.fr/", "http://aegis-test.fr/"],
        ["//cdn.aegis-test.fr/", "https://cdn.aegis-test.fr/"]
    ])("autorise %s", (location, expected) => {
        const decision = evaluateRedirect(location, current, scope);
        expect(decision.allowed).toBe(true);
        if (decision.allowed) expect(decision.url.href).toBe(expected);
    });

    it.each<[string, RedirectRefusal]>([
        ["http://127.0.0.1/", "ip-literal"],
        ["https://169.254.169.254/latest/meta-data/", "ip-literal"],
        ["https://[::1]/", "ip-literal"],
        ["https://[::ffff:127.0.0.1]/", "ip-literal"],
        ["https://0x7f000001/", "ip-literal"],
        ["https://2130706433/", "ip-literal"],
        ["https://aegis-test.fr:8443/", "port"],
        ["http://aegis-test.fr:443/", "port"],
        ["https://aegis-test.fr:22/", "port"],
        ["https://user:secret@aegis-test.fr/", "credentials"],
        ["https://admin@aegis-test.fr/", "credentials"],
        ["ftp://aegis-test.fr/", "unsupported-scheme"],
        ["file:///etc/passwd", "unsupported-scheme"],
        ["javascript:alert(1)", "unsupported-scheme"],
        ["data:text/html,hello", "unsupported-scheme"],
        ["gopher://aegis-test.fr/", "unsupported-scheme"],
        ["https://localhost/", "invalid-host"],
        ["https://metadata.google.internal/", "invalid-host"],
        ["https://intranet/", "invalid-host"],
        ["https://evil.example.com/", "invalid-host"],
        ["https://autre-domaine.fr/", "out-of-scope"],
        ["https://aegis-test.fr.evil.com/", "out-of-scope"],
        ["https://", "invalid-location"],
        ["", "invalid-location"],
        [`/${"a".repeat(3000)}`, "invalid-location"]
    ])("refuse %s (%s)", (location, reason) => {
        const decision = evaluateRedirect(location, current, scope);
        expect(decision).toMatchObject({ allowed: false, reason });
    });

    it("refuse de remonter vers le domaine parent d'un sous-domaine vérifié", () => {
        const decision = evaluateRedirect("https://aegis-test.fr/", new URL("https://app.aegis-test.fr/"), "app.aegis-test.fr");
        expect(decision).toMatchObject({ allowed: false, reason: "out-of-scope" });
    });
});

describe("formatDisplayUrl", () => {
    it("masque les paramètres de requête et tronque les chemins longs", () => {
        expect(formatDisplayUrl(new URL("https://aegis-test.fr/connexion?token=secret&id=1"))).toBe("https://aegis-test.fr/connexion?…");
        expect(formatDisplayUrl(new URL(`https://aegis-test.fr/${"a".repeat(200)}`))).toMatch(/…$/);
        expect(formatDisplayUrl(new URL("https://aegis-test.fr/#fragment"))).toBe("https://aegis-test.fr/");
    });
});
