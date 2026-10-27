import type { APIRoute } from "astro";

const noStore = "no-store";

export function jsonResponse(body: unknown, status = 200): Response {
    return Response.json(body, { status, headers: { "Cache-Control": noStore } });
}

export function errorResponse(status: number, message: string, options: { code?: string; retryAfterMs?: number } = {}): Response {
    const response = jsonResponse(options.code ? { error: message, code: options.code } : { error: message }, status);
    if (options.retryAfterMs !== undefined) response.headers.set("Retry-After", String(Math.max(1, Math.ceil(options.retryAfterMs / 1_000))));
    return response;
}

export function rateLimitedResponse(retryAfterMs: number): Response {
    return errorResponse(429, "Trop de tentatives. Patiente un instant avant de réessayer.", { code: "rate-limited", retryAfterMs });
}

export function methodNotAllowed(allow: string): APIRoute {
    return () => {
        const response = errorResponse(405, "Méthode non autorisée.");
        response.headers.set("Allow", allow);
        return response;
    };
}
