export const checkStatuses = ["pass", "warning", "fail", "not-applicable"] as const;
export type CheckStatus = (typeof checkStatuses)[number];

export const priorities = ["critical", "high", "medium", "low", "info"] as const;
export type Priority = (typeof priorities)[number];

export const categoryIds = ["transport", "tls", "headers", "csp", "cookies", "cache"] as const;
export type CategoryId = (typeof categoryIds)[number];

export interface DocumentationLink {
    label: string;
    url: string;
}

export interface AuditCheck {
    id: string;
    category: CategoryId;
    status: CheckStatus;
    priority: Priority;
    title: string;
    explanation: string;
    recommendation: string | null;
    observed: string | null;
    reference: DocumentationLink | null;
}

export type HeaderMap = ReadonlyMap<string, readonly string[]>;

export interface HttpProbe {
    status: number;
    method: "HEAD" | "GET";
    headers: HeaderMap;
}

export const tlsFailureReasons = [
    "expired",
    "not-yet-valid",
    "hostname-mismatch",
    "self-signed",
    "untrusted-chain",
    "revoked",
    "handshake-failed",
    "connection-refused",
    "timeout",
    "connection-failed"
] as const;
export type TlsFailureReason = (typeof tlsFailureReasons)[number];

export interface CertificateSummary {
    subject: string;
    issuer: string;
    validFrom: number;
    validTo: number;
}

export interface CertificateDetails extends CertificateSummary {
    subjectAltNames: string[];
    key: string | null;
    fingerprint: string;
}

export type TlsObservation =
    | {
        status: "established";
        protocol: string;
        cipher: string;
        certificate: CertificateDetails;
        chain: CertificateSummary[];
    }
    | { status: "failed"; reason: TlsFailureReason };

export const redirectOutcomes = [
    "completed",
    "too-many-redirects",
    "loop",
    "insecure-redirect",
    "missing-location",
    "request-failed",
    "invalid-location",
    "unsupported-scheme",
    "credentials",
    "port",
    "ip-literal",
    "invalid-host",
    "out-of-scope"
] as const;
export type RedirectOutcome = (typeof redirectOutcomes)[number];

export interface RedirectHop {
    url: string;
    status: number;
    method: "HEAD" | "GET";
    location: string | null;
}

export interface RedirectChain {
    hops: RedirectHop[];
    outcome: RedirectOutcome;
    refusedDestination: string | null;
}

export const httpEntryTargets = ["https-same-host", "https-other-host", "http", "refused", "none"] as const;
export type HttpEntryTarget = (typeof httpEntryTargets)[number];

export type HttpEntry =
    | { available: false }
    | { available: true; status: number; target: HttpEntryTarget; location: string | null };

export interface ScanObservations {
    domain: string;
    tls: TlsObservation;
    chain: RedirectChain;
    final: (HttpProbe & { url: string }) | null;
    httpEntry: HttpEntry;
    metaPolicies: string[];
}

export interface HeaderView {
    name: string;
    value: string | null;
    checkId: string | null;
}

export interface CspDirectiveView {
    name: string;
    sources: string[];
}

export interface CspPolicyView {
    mode: "enforce" | "report-only";
    source: "header" | "meta";
    directives: CspDirectiveView[];
}

export type SameSite = "Strict" | "Lax" | "None";

export interface CookieView {
    name: string;
    secure: boolean;
    httpOnly: boolean;
    sameSite: SameSite | null;
    domain: string | null;
    path: string | null;
    lifetime: { kind: "session" } | { kind: "persistent"; seconds: number };
    sensitive: boolean;
    prefix: "__Host-" | "__Secure-" | null;
}

export interface CategoryScore {
    id: CategoryId;
    weight: number;
    earned: number;
    evaluated: boolean;
}

export interface AuditScore {
    value: number;
    categories: CategoryScore[];
}

export interface AuditSummary {
    pass: number;
    warning: number;
    fail: number;
    notApplicable: number;
}

export interface AuditReport {
    version: 1;
    id: string;
    domain: string;
    displayDomain: string;
    startedAt: number;
    durationMs: number;
    expiresAt: number;
    score: AuditScore;
    summary: AuditSummary;
    checks: AuditCheck[];
    tls: TlsObservation;
    redirects: RedirectChain;
    httpEntry: HttpEntry;
    response: { url: string; status: number; method: "HEAD" | "GET" } | null;
    headers: HeaderView[];
    csp: CspPolicyView[];
    cookies: CookieView[];
}
