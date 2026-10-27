import type { APIRoute } from "astro";
import { normalizeHostname } from "@/domain/domain/hostname";
import { cookieNames, readCookie } from "@/lib/http/cookies";
import { readJsonBody } from "@/lib/http/request";
import { errorResponse, jsonResponse, methodNotAllowed, rateLimitedResponse } from "@/lib/http/responses";
import { domainRequestSchema } from "@/lib/validation/api";
import type { AuditError } from "@/services/audits/service";
import { audits, verification } from "@/services/runtime";

export const prerender = false;

const unauthorizedMessage = "Vérifie d'abord la propriété de ce domaine.";
const busyRetryAfterMs = 60_000;

const auditErrors: Record<Exclude<AuditError, "rate-limited">, { status: number; message: string }> = {
    "unauthorized": { status: 403, message: unauthorizedMessage },
    "session-busy": { status: 409, message: "Une analyse est déjà en cours dans cette session." },
    "scanner-busy": { status: 503, message: "L'analyseur est occupé. Réessaie dans une minute." },
    "unresolvable": { status: 422, message: "Ce domaine ne résout vers aucune adresse." },
    "forbidden-address": { status: 422, message: "Ce domaine pointe vers une adresse non publique : l'analyse est refusée." },
    "timeout": { status: 504, message: "L'analyse a dépassé le délai autorisé." },
    "scan-failed": { status: 502, message: "L'analyse n'a pas pu aboutir." }
};

export const POST: APIRoute = async ({ request, url, cookies, clientAddress }) => {
    const body = await readJsonBody(request, url, domainRequestSchema);
    if (!body.ok) return body.response;

    const normalized = normalizeHostname(body.data.domain);
    const session = verification.readSession(readCookie(cookies, cookieNames.session));
    if (!normalized.ok || !session) return errorResponse(403, unauthorizedMessage, { code: "unauthorized" });

    const result = await audits.startAudit({
        session,
        proofToken: readCookie(cookies, cookieNames.proof),
        domain: normalized.hostname.ascii,
        client: clientAddress,
        signal: request.signal
    });
    if (result.ok) return jsonResponse({ id: result.report.id, expiresAt: result.report.expiresAt }, 201);
    if (result.error === "rate-limited") return rateLimitedResponse(result.retryAfterMs ?? busyRetryAfterMs);

    const { status, message } = auditErrors[result.error];
    return errorResponse(status, message, {
        code: result.error,
        retryAfterMs: result.error === "scanner-busy" ? busyRetryAfterMs : undefined
    });
};

export const ALL = methodNotAllowed("POST");
