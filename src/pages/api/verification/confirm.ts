import type { APIRoute } from "astro";
import { clearCookie, cookieNames, readCookie, writeCookie } from "@/lib/http/cookies";
import { readJsonBody } from "@/lib/http/request";
import { errorResponse, jsonResponse, methodNotAllowed, rateLimitedResponse } from "@/lib/http/responses";
import { emptyRequestSchema } from "@/lib/validation/api";
import { verification } from "@/services/runtime";

export const prerender = false;

export const POST: APIRoute = async ({ request, url, cookies, clientAddress }) => {
    const body = await readJsonBody(request, url, emptyRequestSchema);
    if (!body.ok) return body.response;

    const session = verification.openSession(readCookie(cookies, cookieNames.session));
    const result = await verification.confirmChallenge({
        session: session.payload,
        challengeToken: readCookie(cookies, cookieNames.challenge),
        client: clientAddress
    });

    if (!result.ok) {
        if (result.error === "rate-limited") return rateLimitedResponse(result.retryAfterMs);
        clearCookie(cookies, cookieNames.challenge);
        return result.error === "attempts-exhausted"
            ? errorResponse(429, "Nombre maximal de vérifications atteint : génère un nouveau challenge.", { code: result.error })
            : errorResponse(409, "Aucun challenge actif pour cette session : génère un nouveau challenge.", { code: result.error });
    }

    writeCookie(cookies, cookieNames.session, session.token, session.payload.exp);
    if (result.status === "pending") {
        const { reason, attemptsRemaining, retryAfterMs } = result;
        return jsonResponse({ status: "pending", reason, attemptsRemaining, retryAfterMs });
    }

    clearCookie(cookies, cookieNames.challenge);
    writeCookie(cookies, cookieNames.proof, result.proofToken, result.expiresAt);
    return jsonResponse({ status: "verified", domain: result.domain, expiresAt: result.expiresAt });
};

export const ALL = methodNotAllowed("POST");
