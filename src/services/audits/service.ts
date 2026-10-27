import { domainToUnicode } from "node:url";
import type { AuditReport } from "@/domain/audit/model";
import { buildReport } from "@/domain/audit/report";
import type { SessionToken } from "@/domain/verification/tokens";
import { createRandomToken } from "@/lib/crypto/random";
import { logEvent } from "@/lib/logging";
import type { SocketConnector } from "@/lib/network/connector";
import { NetworkError } from "@/lib/network/errors";
import type { AddressResolver } from "@/lib/network/resolve";
import { createExpiringStore } from "@/lib/state/expiring-store";
import { consumeAll, createRateLimiter } from "@/lib/state/rate-limiter";
import { createHostPinner } from "@/services/scanner/context";
import { runScan } from "@/services/scanner/scan";
import type { VerificationService } from "@/services/verification/service";

export const auditPolicy = {
    reportTtlMs: 30 * 60_000,
    maxReports: 500,
    requestTimeoutMs: 6_000,
    scanTimeoutMs: 25_000,
    maxConcurrentScans: 3,
    limitWindowMs: 60 * 60_000
} as const;

export type AuditError =
    | "unauthorized"
    | "rate-limited"
    | "session-busy"
    | "scanner-busy"
    | "unresolvable"
    | "forbidden-address"
    | "timeout"
    | "scan-failed";

export type AuditResult = { ok: true; report: AuditReport } | { ok: false; error: AuditError; retryAfterMs?: number };

export interface AuditService {
    startAudit: (input: { session: SessionToken; proofToken: string | undefined; domain: string; client: string; signal: AbortSignal }) => Promise<AuditResult>;
    getReport: (input: { session: SessionToken; id: string }) => AuditReport | null;
}

interface AuditDependencies {
    verification: Pick<VerificationService, "readProof">;
    resolver: AddressResolver;
    connector: SocketConnector;
    now?: () => number;
}

interface StoredReport {
    sessionId: string;
    report: AuditReport;
}

const networkErrors: Partial<Record<NetworkError["code"], AuditError>> = {
    "dns-not-found": "unresolvable",
    "dns-failure": "unresolvable",
    "forbidden-address": "forbidden-address",
    "aborted": "timeout",
    "timeout": "timeout"
};

function toAuditError(error: unknown): AuditError {
    return error instanceof NetworkError ? networkErrors[error.code] ?? "scan-failed" : "scan-failed";
}

export function createAuditService({ verification, resolver, connector, now = Date.now }: AuditDependencies): AuditService {
    const reports = createExpiringStore<StoredReport>({ maxEntries: auditPolicy.maxReports, now });
    const limiterOptions = { windowMs: auditPolicy.limitWindowMs, maxKeys: 10_000, now };
    const bySession = createRateLimiter({ ...limiterOptions, limit: 5 });
    const byDomain = createRateLimiter({ ...limiterOptions, limit: 5 });
    const byClient = createRateLimiter({ ...limiterOptions, limit: 10 });
    const activeSessions = new Set<string>();

    const scan = async (session: SessionToken, domain: string, signal: AbortSignal): Promise<AuditResult> => {
        const startedAt = now();
        const context = {
            connector,
            pinHost: createHostPinner(resolver),
            deadline: { timeoutMs: auditPolicy.requestTimeoutMs, signal: AbortSignal.any([signal, AbortSignal.timeout(auditPolicy.scanTimeoutMs)]) }
        };
        try {
            const observations = await runScan(domain, context);
            const completedAt = now();
            const report = buildReport({
                id: createRandomToken(),
                displayDomain: domainToUnicode(domain),
                observations,
                startedAt,
                completedAt,
                expiresAt: completedAt + auditPolicy.reportTtlMs
            });
            reports.set(report.id, { sessionId: session.sid, report }, auditPolicy.reportTtlMs);
            logEvent("info", "audit.completed", { durationMs: report.durationMs, score: report.score.value, failures: report.summary.fail });
            return { ok: true, report };
        } catch (error) {
            const auditError = toAuditError(error);
            logEvent("warn", "audit.failed", { reason: auditError, durationMs: now() - startedAt });
            return { ok: false, error: auditError };
        }
    };

    const startAudit: AuditService["startAudit"] = async ({ session, proofToken, domain, client, signal }) => {
        if (!verification.readProof({ session, proofToken, domain })) return { ok: false, error: "unauthorized" };
        if (activeSessions.has(session.sid)) return { ok: false, error: "session-busy" };
        if (activeSessions.size >= auditPolicy.maxConcurrentScans) return { ok: false, error: "scanner-busy" };
        const limit = consumeAll([[bySession, session.sid], [byDomain, domain], [byClient, client]]);
        if (!limit.allowed) return { ok: false, error: "rate-limited", retryAfterMs: limit.retryAfterMs };

        activeSessions.add(session.sid);
        try {
            return await scan(session, domain, signal);
        } finally {
            activeSessions.delete(session.sid);
        }
    };

    const getReport: AuditService["getReport"] = ({ session, id }) => {
        const stored = reports.get(id);
        return stored && stored.sessionId === session.sid ? stored.report : null;
    };

    return { startAudit, getReport };
}
