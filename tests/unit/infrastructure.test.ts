import { describe, expect, it } from "vitest";
import { NetworkError, toNetworkError } from "@/lib/network/errors";
import { resolvePinnedHost } from "@/lib/network/resolve";
import { createExpiringStore } from "@/lib/state/expiring-store";
import { consumeAll, createRateLimiter } from "@/lib/state/rate-limiter";
import { parseDnsServers } from "@/services/dns/resolver";
import { toHeaderMap } from "@/services/scanner/http-client";
import { classifyTlsFailure } from "@/services/tls/inspect";

function createClock(start = 0) {
    let time = start;
    return { now: () => time, advance: (milliseconds: number) => { time += milliseconds; } };
}

function resolver(ipv4: string[], ipv6: string[] = []) {
    return { resolve4: async () => ipv4, resolve6: async () => ipv6 };
}

describe("createExpiringStore", () => {
    it("expire les entrées et borne leur nombre", () => {
        const clock = createClock();
        const store = createExpiringStore<number>({ maxEntries: 2, now: clock.now });
        store.set("a", 1, 100);
        store.set("b", 2, 100);
        store.set("c", 3, 100);
        expect(store.get("a")).toBeUndefined();
        expect(store.get("c")).toBe(3);
        clock.advance(100);
        expect(store.get("b")).toBeUndefined();
        expect(store.size()).toBeLessThanOrEqual(2);
    });
});

describe("createRateLimiter", () => {
    it("limite par fenêtre et indique le délai d'attente", () => {
        const clock = createClock();
        const limiter = createRateLimiter({ limit: 2, windowMs: 1_000, maxKeys: 10, now: clock.now });
        expect(limiter.consume("ip").allowed).toBe(true);
        expect(limiter.consume("ip").allowed).toBe(true);
        expect(limiter.consume("ip")).toEqual({ allowed: false, retryAfterMs: 1_000 });
        expect(limiter.consume("autre").allowed).toBe(true);
        clock.advance(1_000);
        expect(limiter.consume("ip").allowed).toBe(true);
    });

    it("refuse dès qu'une limite combinée est atteinte", () => {
        const first = createRateLimiter({ limit: 1, windowMs: 1_000, maxKeys: 10 });
        const second = createRateLimiter({ limit: 5, windowMs: 1_000, maxKeys: 10 });
        expect(consumeAll([[first, "a"], [second, "a"]]).allowed).toBe(true);
        expect(consumeAll([[first, "a"], [second, "a"]]).allowed).toBe(false);
    });
});

describe("resolvePinnedHost", () => {
    it("épingle la première adresse IPv4 publique", async () => {
        await expect(resolvePinnedHost("aegis-test.fr", resolver(["93.184.215.14", "93.184.215.15"], ["2606:4700::1"])))
            .resolves.toEqual({ hostname: "aegis-test.fr", address: "93.184.215.14", family: 4 });
        await expect(resolvePinnedHost("aegis-test.fr", resolver([], ["2606:4700::1"]))).resolves.toMatchObject({ family: 6 });
    });

    it.each([
        [["93.184.215.14", "10.0.0.1"], []],
        [["127.0.0.1"], []],
        [["93.184.215.14"], ["::1"]],
        [[], ["fd00::1"]],
        [["169.254.169.254"], []]
    ])("refuse une réponse contenant une adresse interdite %#", async (ipv4, ipv6) => {
        await expect(resolvePinnedHost("aegis-test.fr", resolver(ipv4, ipv6))).rejects.toMatchObject({ code: "forbidden-address" });
    });

    it("signale un domaine sans adresse", async () => {
        await expect(resolvePinnedHost("aegis-test.fr", resolver([]))).rejects.toMatchObject({ code: "dns-not-found" });
    });
});

describe("parseDnsServers", () => {
    it("accepte uniquement des adresses IP de résolveurs", () => {
        expect(parseDnsServers("1.1.1.1, 9.9.9.9")).toEqual(["1.1.1.1", "9.9.9.9"]);
        expect(parseDnsServers("127.0.0.1:5353,[2606:4700:4700::1111]:53")).toHaveLength(2);
        for (const value of ["", "dns.google", "1.1.1.1:99999", "https://1.1.1.1"]) expect(() => parseDnsServers(value)).toThrow();
    });
});

describe("erreurs réseau", () => {
    it("normalise les erreurs de socket sans exposer de détail", () => {
        expect(toNetworkError(Object.assign(new Error("connect ECONNREFUSED 10.0.0.1:443"), { code: "ECONNREFUSED" }))).toMatchObject({ code: "connection-refused", message: "connection-refused" });
        expect(toNetworkError(Object.assign(new Error("x"), { code: "CERT_HAS_EXPIRED" })).code).toBe("tls-failure");
        expect(toNetworkError(Object.assign(new Error("x"), { code: "HPE_INVALID_CONSTANT" })).code).toBe("invalid-response");
        expect(toNetworkError("inattendu").code).toBe("connection-failed");
    });

    it.each([
        ["CERT_HAS_EXPIRED", "expired"],
        ["ERR_TLS_CERT_ALTNAME_INVALID", "hostname-mismatch"],
        ["DEPTH_ZERO_SELF_SIGNED_CERT", "self-signed"],
        ["UNABLE_TO_VERIFY_LEAF_SIGNATURE", "untrusted-chain"],
        ["ERR_SSL_WRONG_VERSION_NUMBER", "handshake-failed"],
        ["ECONNREFUSED", "connection-refused"]
    ])("classe l'erreur TLS %s", (code, reason) => {
        expect(classifyTlsFailure(Object.assign(new Error(code), { code }))).toBe(reason);
        expect(classifyTlsFailure(new NetworkError("timeout"))).toBe("timeout");
    });
});

describe("toHeaderMap", () => {
    it("regroupe les en-têtes répétés en minuscules et borne leur nombre", () => {
        const headers = toHeaderMap(["Set-Cookie", "a=1", "set-cookie", "b=2", "X-Test", "v"]);
        expect(headers.get("set-cookie")).toEqual(["a=1", "b=2"]);
        expect(toHeaderMap(Array.from({ length: 1000 }, (_, index) => `h${index}`)).size).toBeLessThanOrEqual(120);
    });
});
