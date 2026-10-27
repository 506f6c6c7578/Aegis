import type { APIRoute } from "astro";
import { normalizeHostname } from "@/domain/domain/hostname";
import { hostnameErrorMessages } from "@/domain/domain/input";
import { clearCookie, cookieNames, readCookie, writeCookie } from "@/lib/http/cookies";
import { readJsonBody } from "@/lib/http/request";
import { errorResponse, jsonResponse, methodNotAllowed, rateLimitedResponse } from "@/lib/http/responses";
import { domainRequestSchema } from "@/lib/validation/api";
import { verification } from "@/services/runtime";

export const prerender = false;

export const POST: APIRoute = async ({ request, url, cookies, clientAddress }) => {
    const body = await readJsonBody(request, url, domainRequestSchema);
    if (!body.ok) return body.response;

    const normalized = normalizeHostname(body.data.domain);
    if (!normalized.ok) return errorResponse(422, hostnameErrorMessages[normalized.error], { code: normalized.error });

    const session = verification.openSession(readCookie(cookies, cookieNames.session));
    const result = verification.issueChallenge({ session: session.payload, hostname: normalized.hostname, client: clientAddress });
    if (!result.ok) return rateLimitedResponse(result.retryAfterMs);

    writeCookie(cookies, cookieNames.session, session.token, session.payload.exp);
    writeCookie(cookies, cookieNames.challenge, result.challengeToken, result.challenge.expiresAt);
    clearCookie(cookies, cookieNames.proof);
    return jsonResponse({ challenge: result.challenge }, 201);
};

export const ALL = methodNotAllowed("POST");
