import { createHash } from "node:crypto";

export function getScriptHash(code: string): `sha256-${string}` {
    return `sha256-${createHash("sha256").update(code).digest("base64")}`;
}
