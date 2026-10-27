import * as z from "zod/mini";
import { endpoints, getAuditEndpoint } from "@/data/site";
import type { AuditReport } from "@/domain/audit/model";
import { type Confirmation, type IssuedChallenge, pendingReasons } from "@/domain/verification/model";
import { reportSchema } from "@/lib/validation/report";

const genericError = "Le service ne répond pas. Réessaie dans quelques instants.";

export class ApiError extends Error {
    override readonly name = "ApiError";

    constructor(readonly status: number, message: string, readonly code: string | null, readonly retryAfterMs: number | null) {
        super(message);
    }
}

const errorSchema = z.object({ error: z.string().check(z.maxLength(300)), code: z.optional(z.string()) });

export const challengeSchema: z.ZodMiniType<IssuedChallenge> = z.object({
    domain: z.string(),
    displayDomain: z.string(),
    recordName: z.string(),
    recordValue: z.string(),
    expiresAt: z.number()
});

const confirmationSchema: z.ZodMiniType<Confirmation> = z.union([
    z.object({
        status: z.literal("pending"),
        reason: z.enum(pendingReasons),
        attemptsRemaining: z.int(),
        retryAfterMs: z.int()
    }),
    z.object({ status: z.literal("verified"), domain: z.string(), expiresAt: z.number() })
]);

const auditStartSchema = z.object({ id: z.string(), expiresAt: z.number() });

function readRetryAfter(response: Response): number | null {
    const seconds = Number(response.headers.get("retry-after"));
    return Number.isFinite(seconds) && seconds > 0 ? seconds * 1_000 : null;
}

async function toApiError(response: Response): Promise<ApiError> {
    const body = errorSchema.safeParse(await response.json().catch(() => null));
    return new ApiError(
        response.status,
        body.success ? body.data.error : genericError,
        body.success ? body.data.code ?? null : null,
        readRetryAfter(response)
    );
}

async function request<Output>(url: string, schema: z.ZodMiniType<Output>, init: RequestInit): Promise<Output> {
    let response: Response;
    try {
        response = await fetch(url, {
            ...init,
            credentials: "same-origin",
            headers: { "Accept": "application/json", ...(init.body ? { "Content-Type": "application/json" } : {}) }
        });
    } catch (error) {
        if (error instanceof DOMException && error.name === "AbortError") throw error;
        throw new ApiError(0, genericError, null, null);
    }
    if (!response.ok) throw await toApiError(response);
    const result = schema.safeParse(await response.json().catch(() => null));
    if (!result.success) throw new ApiError(response.status, genericError, null, null);
    return result.data;
}

function post<Output>(url: string, schema: z.ZodMiniType<Output>, body: object): Promise<Output> {
    return request(url, schema, { method: "POST", body: JSON.stringify(body) });
}

export const api = {
    createChallenge: async (domain: string): Promise<IssuedChallenge> =>
        (await post(endpoints.challenge, z.object({ challenge: challengeSchema }), { domain })).challenge,
    confirmChallenge: (): Promise<Confirmation> => post(endpoints.confirm, confirmationSchema, {}),
    startAudit: (domain: string): Promise<{ id: string; expiresAt: number }> => post(endpoints.audits, auditStartSchema, { domain }),
    getReport: async (id: string, signal: AbortSignal): Promise<AuditReport> =>
        (await request(getAuditEndpoint(id), z.object({ report: reportSchema }), { method: "GET", signal })).report
};
