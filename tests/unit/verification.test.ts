import { describe, expect, it } from "vitest";
import * as z from "zod/mini";
import { hashChallengeToken, matchesChallenge } from "@/domain/verification/challenge";
import { getVerificationRecordName } from "@/domain/verification/policy";
import { challengeTokenSchema } from "@/domain/verification/tokens";
import { safeEqual, sha256 } from "@/lib/crypto/hash";
import { createRandomToken, randomTokenPattern } from "@/lib/crypto/random";
import { createTokenSigner } from "@/lib/crypto/signed-token";

const secret = "test-secret-with-enough-entropy-for-hkdf-derivation";
const now = 1_800_000_000_000;
const payloadSchema = z.object({ value: z.string(), exp: z.number() });

describe("createRandomToken", () => {
    it("produit des jetons de 256 bits encodés en base64url, tous différents", () => {
        const tokens = new Set(Array.from({ length: 200 }, createRandomToken));
        expect(tokens.size).toBe(200);
        for (const token of tokens) expect(token).toMatch(randomTokenPattern);
    });
});

describe("safeEqual et sha256", () => {
    it("compare en temps constant et gère des longueurs différentes", () => {
        expect(safeEqual("abc", "abc")).toBe(true);
        expect(safeEqual("abc", "abd")).toBe(false);
        expect(safeEqual("abc", "abcd")).toBe(false);
        expect(sha256("aegis")).toMatch(randomTokenPattern);
    });
});

describe("createTokenSigner", () => {
    const signer = createTokenSigner(secret);
    const token = signer.sign("challenge", { value: "exemple", exp: now + 1_000 });

    it("vérifie un jeton valide", () => {
        expect(signer.verify("challenge", token, payloadSchema, now)).toEqual({ value: "exemple", exp: now + 1_000 });
    });

    it("refuse un jeton expiré", () => {
        expect(signer.verify("challenge", token, payloadSchema, now + 1_000)).toBeNull();
    });

    it("refuse un jeton signé pour un autre usage", () => {
        expect(signer.verify("proof", token, payloadSchema, now)).toBeNull();
        expect(signer.verify("session", token, payloadSchema, now)).toBeNull();
    });

    it("refuse un jeton signé avec un autre secret", () => {
        expect(createTokenSigner(`${secret}-autre`).verify("challenge", token, payloadSchema, now)).toBeNull();
    });

    it("refuse un contenu modifié", () => {
        const [, signature] = token.split(".");
        const forged = `${Buffer.from(JSON.stringify({ value: "pirate", exp: now + 1_000 })).toString("base64url")}.${signature}`;
        expect(signer.verify("challenge", forged, payloadSchema, now)).toBeNull();
    });

    it.each([undefined, "", "abc", "a.b", `${token}x`, `${"a".repeat(3000)}.${"b".repeat(43)}`, token.replace(".", "..")])("refuse le jeton mal formé %#", (value) => {
        expect(signer.verify("challenge", value, payloadSchema, now)).toBeNull();
    });

    it("refuse un contenu authentique mais non conforme au schéma", () => {
        const valid = signer.sign("challenge", { value: "exemple", exp: now + 1_000 });
        expect(signer.verify("challenge", valid, challengeTokenSchema, now)).toBeNull();
    });
});

describe("challenge DNS", () => {
    const binding = { challengeId: createRandomToken(), domain: "aegis-test.fr" };
    const token = createRandomToken();
    const hash = hashChallengeToken(binding, token);

    it("nomme l'enregistrement TXT d'après le domaine exact", () => {
        expect(getVerificationRecordName("aegis-test.fr")).toBe("_aegis-verify.aegis-test.fr");
    });

    it("ne stocke qu'une empreinte liée au challenge et au domaine", () => {
        expect(hash).not.toContain(token);
        expect(hashChallengeToken({ ...binding, domain: "autre.fr" }, token)).not.toBe(hash);
        expect(hashChallengeToken({ ...binding, challengeId: createRandomToken() }, token)).not.toBe(hash);
    });

    it("reconnaît le jeton parmi plusieurs enregistrements, découpés ou entre guillemets", () => {
        expect(matchesChallenge([["v=spf1 -all"], [token]], binding, hash)).toBe(true);
        expect(matchesChallenge([[token.slice(0, 20), token.slice(20)]], binding, hash)).toBe(true);
        expect(matchesChallenge([[`"${token}"`]], binding, hash)).toBe(true);
        expect(matchesChallenge([[` ${token} `]], binding, hash)).toBe(true);
    });

    it("refuse une valeur absente, différente ou partielle", () => {
        expect(matchesChallenge([], binding, hash)).toBe(false);
        expect(matchesChallenge([[createRandomToken()]], binding, hash)).toBe(false);
        expect(matchesChallenge([[token.slice(0, -1)]], binding, hash)).toBe(false);
        expect(matchesChallenge([[`${token}x`]], binding, hash)).toBe(false);
        expect(matchesChallenge([[`aegis=${token}`]], binding, hash)).toBe(false);
    });
});
