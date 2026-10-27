import { describe, expect, it } from "vitest";
import { normalizeHostname } from "@/domain/domain/hostname";
import { detectHostnameShapeError, type HostnameError, isSameOrSubdomain } from "@/domain/domain/input";

function errorOf(input: string): HostnameError | null {
    const result = normalizeHostname(input);
    return result.ok ? null : result.error;
}

describe("normalizeHostname", () => {
    it.each([
        ["paulviandier.com", "paulviandier.com"],
        ["  PaulViandier.COM  ", "paulviandier.com"],
        ["paulviandier.com.", "paulviandier.com"],
        ["www.exemple.co.uk", "www.exemple.co.uk"],
        ["sous-domaine.exemple.fr", "sous-domaine.exemple.fr"],
        ["Bücher.de", "xn--bcher-kva.de"],
        ["xn--bcher-kva.de", "xn--bcher-kva.de"],
        ["ｅxemple.fr", "exemple.fr"]
    ])("normalise %s en %s", (input, ascii) => {
        const result = normalizeHostname(input);
        expect(result).toMatchObject({ ok: true, hostname: { ascii } });
    });

    it("conserve la forme Unicode pour l'affichage", () => {
        expect(normalizeHostname("bücher.de")).toEqual({ ok: true, hostname: { ascii: "xn--bcher-kva.de", unicode: "bücher.de" } });
    });

    it.each<[string, HostnameError]>([
        ["", "empty"],
        ["   ", "empty"],
        ["https://exemple.fr", "url"],
        ["http://exemple.fr/", "url"],
        ["ftp://exemple.fr", "url"],
        ["//exemple.fr", "url"],
        ["user:pass@exemple.fr", "credentials"],
        ["admin@exemple.fr", "credentials"],
        ["*.exemple.fr", "wildcard"],
        ["exemple.fr/admin", "path"],
        ["exemple.fr?q=1", "path"],
        ["exemple.fr#fragment", "path"],
        ["exemple.fr\\chemin", "path"],
        ["exemple.fr:8443", "port"],
        ["exemple.fr:443", "port"],
        ["127.0.0.1", "ip-address"],
        ["8.8.8.8", "ip-address"],
        ["[::1]", "ip-address"],
        ["::1", "ip-address"],
        ["2606:4700::1111", "ip-address"],
        ["１２７.0.0.1", "ip-address"],
        ["exemple%2efr", "invalid-characters"],
        ["exem ple.fr", "invalid-characters"],
        ["exemple_test.fr", "invalid-characters"],
        ["exemple.fr\u0000", "invalid-characters"],
        ["localhost", "single-label"],
        ["intranet", "single-label"],
        ["-exemple.fr", "invalid-label"],
        ["exemple-.fr", "invalid-label"],
        ["exemple..fr", "invalid-label"],
        ["ab--exemple.fr", "invalid-label"],
        ["exemple.123", "invalid-label"],
        [`${"a".repeat(64)}.fr`, "invalid-label"],
        ["app.localhost", "special-use"],
        ["imprimante.local", "special-use"],
        ["serveur.internal", "special-use"],
        ["nas.lan", "special-use"],
        ["poste.corp", "special-use"],
        ["site.test", "special-use"],
        ["site.example", "special-use"],
        ["example.com", "special-use"],
        ["service.onion", "special-use"],
        ["routeur.home.arpa", "special-use"],
        ["1.0.0.127.in-addr.arpa", "special-use"],
        ["exemple.inexistant", "not-public"],
        ["co.uk", "public-suffix"],
        ["fr", "single-label"],
        [`${"a.".repeat(120)}fr`, "too-long"]
    ])("refuse %j (%s)", (input, error) => {
        expect(errorOf(input)).toBe(error);
    });

    it("borne le domaine pour que le nom de l'enregistrement TXT reste valide", () => {
        const domainOfLength = (length: number) => `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(length - 195)}.fr`;
        expect(domainOfLength(239)).toHaveLength(239);
        expect(normalizeHostname(domainOfLength(239)).ok).toBe(true);
        expect(errorOf(domainOfLength(240))).toBe("too-long");
    });
});

describe("detectHostnameShapeError", () => {
    it("ne rejette pas un nom d'hôte bien formé", () => {
        expect(detectHostnameShapeError("exemple.fr")).toBeNull();
        expect(detectHostnameShapeError("bücher.de")).toBeNull();
    });

    it("signale les entrées manifestement invalides côté client", () => {
        expect(detectHostnameShapeError("https://exemple.fr")).toBe("url");
        expect(detectHostnameShapeError("exemple.fr:80")).toBe("port");
        expect(detectHostnameShapeError("10.0.0.1")).toBe("ip-address");
    });
});

describe("isSameOrSubdomain", () => {
    it.each([
        ["exemple.fr", "exemple.fr", true],
        ["www.exemple.fr", "exemple.fr", true],
        ["a.b.exemple.fr", "exemple.fr", true],
        ["exemple.fr", "www.exemple.fr", false],
        ["autreexemple.fr", "exemple.fr", false],
        ["exemple.fr.evil.com", "exemple.fr", false]
    ])("%s dans %s : %s", (hostname, domain, expected) => {
        expect(isSameOrSubdomain(hostname, domain)).toBe(expected);
    });
});
