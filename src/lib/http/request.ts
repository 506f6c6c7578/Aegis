import type * as z from "zod/mini";
import { errorResponse } from "@/lib/http/responses";

export const maxJsonBodyBytes = 1024;

export type JsonBody<Output> = { ok: true; data: Output } | { ok: false; response: Response };

export function isSameOrigin(request: Request, url: URL): boolean {
    const fetchSite = request.headers.get("sec-fetch-site");
    if (fetchSite !== null && fetchSite !== "same-origin") return false;
    return request.headers.get("origin") === url.origin;
}

function failure<Output>(status: number, message: string): JsonBody<Output> {
    return { ok: false, response: errorResponse(status, message) };
}

function parseJson(text: string): unknown {
    try {
        return JSON.parse(text);
    } catch {
        return undefined;
    }
}

export async function readJsonBody<Output>(request: Request, url: URL, schema: z.ZodMiniType<Output>): Promise<JsonBody<Output>> {
    if (!isSameOrigin(request, url)) return failure(403, "Requête refusée.");
    if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) return failure(415, "Le corps de la requête doit être au format JSON.");
    if (Number(request.headers.get("content-length") ?? 0) > maxJsonBodyBytes) return failure(413, "Requête trop volumineuse.");

    let text: string;
    try {
        text = await request.text();
    } catch {
        return failure(413, "Requête trop volumineuse.");
    }
    if (Buffer.byteLength(text, "utf8") > maxJsonBodyBytes) return failure(413, "Requête trop volumineuse.");

    const result = schema.safeParse(parseJson(text));
    return result.success ? { ok: true, data: result.data } : failure(400, "Requête invalide.");
}
