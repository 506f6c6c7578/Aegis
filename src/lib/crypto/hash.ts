import { createHash, timingSafeEqual } from "node:crypto";

export function sha256(value: string): string {
    return createHash("sha256").update(value, "utf8").digest("base64url");
}

export function safeEqual(first: string, second: string): boolean {
    const firstBuffer = Buffer.from(first, "utf8");
    const secondBuffer = Buffer.from(second, "utf8");
    return firstBuffer.length === secondBuffer.length && timingSafeEqual(firstBuffer, secondBuffer);
}
