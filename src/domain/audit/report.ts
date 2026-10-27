import { analyzeCache, cacheCheckIds } from "@/domain/audit/cache";
import { getHeader, maskObserved } from "@/domain/audit/checks";
import { analyzeCookies, parseCookies } from "@/domain/audit/cookies";
import { analyzeCsp, cspCheckIds, parseContentSecurityPolicies } from "@/domain/audit/csp";
import { analyzeHeaders, headerCheckIds } from "@/domain/audit/headers";
import type { AuditReport, CategoryId, HeaderMap, HeaderView, ScanObservations } from "@/domain/audit/model";
import { computeScore, summarize } from "@/domain/audit/score";
import { analyzeTls } from "@/domain/audit/tls";
import { analyzeTransport, transportCheckIds } from "@/domain/audit/transport";

const reportedHeaders: readonly [name: string, checkId: string | null][] = [
    ["content-security-policy", cspCheckIds.present],
    ["content-security-policy-report-only", cspCheckIds.present],
    ["strict-transport-security", transportCheckIds.hsts],
    ["x-content-type-options", headerCheckIds.contentType],
    ["referrer-policy", headerCheckIds.referrer],
    ["permissions-policy", headerCheckIds.permissions],
    ["cross-origin-opener-policy", headerCheckIds.opener],
    ["cross-origin-resource-policy", headerCheckIds.resource],
    ["cross-origin-embedder-policy", headerCheckIds.embedder],
    ["x-frame-options", headerCheckIds.framing],
    ["cache-control", cacheCheckIds.cacheControl],
    ["pragma", cacheCheckIds.cacheControl],
    ["expires", cacheCheckIds.cacheControl],
    ["server", cacheCheckIds.disclosure],
    ["x-powered-by", cacheCheckIds.disclosure]
];

function toHeaderViews(headers: HeaderMap): HeaderView[] {
    return reportedHeaders.map(([name, checkId]) => {
        const value = getHeader(headers, name);
        return { name, value: value === null ? null : maskObserved(value), checkId };
    });
}

export interface ReportInput {
    id: string;
    displayDomain: string;
    observations: ScanObservations;
    startedAt: number;
    completedAt: number;
    expiresAt: number;
}

export function buildReport({ id, displayDomain, observations, startedAt, completedAt, expiresAt }: ReportInput): AuditReport {
    const { final, tls } = observations;
    const headers: HeaderMap = final?.headers ?? new Map();
    const csp = parseContentSecurityPolicies(headers, observations.metaPolicies);
    const cookies = parseCookies(headers, completedAt);
    const responseChecks = final
        ? [...analyzeHeaders(headers, csp), ...analyzeCsp(csp), ...analyzeCookies(cookies), ...analyzeCache(headers, cookies)]
        : [];
    const checks = [...analyzeTransport(observations, completedAt), ...analyzeTls(tls), ...responseChecks];
    const evaluated = new Set<CategoryId>(["transport"]);
    if (tls.status === "established") evaluated.add("tls");
    if (final) for (const category of ["headers", "csp", "cookies", "cache"] as const) evaluated.add(category);

    return {
        version: 1,
        id,
        domain: observations.domain,
        displayDomain,
        startedAt,
        durationMs: completedAt - startedAt,
        expiresAt,
        score: computeScore(checks, evaluated),
        summary: summarize(checks),
        checks,
        tls,
        redirects: observations.chain,
        httpEntry: observations.httpEntry,
        response: final ? { url: final.url, status: final.status, method: final.method } : null,
        headers: final ? toHeaderViews(headers) : [],
        csp,
        cookies
    };
}
