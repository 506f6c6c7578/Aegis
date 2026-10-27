import { createHmac, hkdfSync } from "node:crypto";
import type * as z from "zod/mini";
import { safeEqual } from "@/lib/crypto/hash";

const tokenPurposes = ["session", "challenge", "proof"] as const;
const maxTokenLength = 2048;
const tokenPattern = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/;

export type TokenPurpose = (typeof tokenPurposes)[number];

export interface ExpiringPayload {
    exp: number;
}

export interface TokenSigner {
    sign: <Payload extends ExpiringPayload>(purpose: TokenPurpose, payload: Payload) => string;
    verify: <Payload extends ExpiringPayload>(
        purpose: TokenPurpose,
        token: string | undefined,
        schema: z.ZodMiniType<Payload>,
        now: number
    ) => Payload | null;
}

function deriveKey(secret: string, purpose: TokenPurpose): Buffer {
    return Buffer.from(hkdfSync("sha256", secret, "aegis", `aegis:${purpose}:v1`, 32));
}

function parsePayload(encoded: string): unknown {
    try {
        return JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    } catch {
        return null;
    }
}

export function createTokenSigner(secret: string): TokenSigner {
    const keys = new Map(tokenPurposes.map((purpose) => [purpose, deriveKey(secret, purpose)]));

    const authenticate = (purpose: TokenPurpose, encoded: string) => {
        const key = keys.get(purpose);
        if (!key) throw new Error("Usage de jeton inconnu.");
        return createHmac("sha256", key).update(`${purpose}.${encoded}`).digest("base64url");
    };

    return {
        sign: (purpose, payload) => {
            const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
            return `${encoded}.${authenticate(purpose, encoded)}`;
        },
        verify: (purpose, token, schema, now) => {
            if (!token || token.length > maxTokenLength || !tokenPattern.test(token)) return null;
            const [encoded = "", signature = ""] = token.split(".");
            if (!safeEqual(signature, authenticate(purpose, encoded))) return null;
            const result = schema.safeParse(parsePayload(encoded));
            return result.success && result.data.exp > now ? result.data : null;
        }
    };
}
