import { randomBytes } from "node:crypto";

const tokenByteLength = 32;

export const randomTokenPattern = /^[A-Za-z0-9_-]{43}$/;

export function createRandomToken(): string {
    return randomBytes(tokenByteLength).toString("base64url");
}
