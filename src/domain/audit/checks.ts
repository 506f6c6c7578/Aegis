import type { AuditCheck, CategoryId, DocumentationLink, HeaderMap } from "@/domain/audit/model";

export interface CheckDefinition {
    id: string;
    category: CategoryId;
    title: string;
    reference: DocumentationLink | null;
}

export type CheckOutcome = Pick<AuditCheck, "status" | "priority" | "explanation"> &
    Partial<Pick<AuditCheck, "recommendation" | "observed">>;

const maxObservedLength = 600;
const urlQueryPattern = /(\b[a-z][a-z0-9+.-]*:\/\/[^\s;,'"?]*)\?[^\s;,'"]*/gi;

export function maskObserved(value: string): string {
    const masked = value.replace(/\p{Cc}/gu, " ").replace(urlQueryPattern, "$1?…").trim();
    return masked.length > maxObservedLength ? `${masked.slice(0, maxObservedLength)}…` : masked;
}

export function createCheck(definition: CheckDefinition, outcome: CheckOutcome): AuditCheck {
    return {
        ...definition,
        status: outcome.status,
        priority: outcome.priority,
        explanation: outcome.explanation,
        recommendation: outcome.recommendation ?? null,
        observed: outcome.observed === undefined || outcome.observed === null ? null : maskObserved(outcome.observed)
    };
}

export function getHeaderValues(headers: HeaderMap, name: string): readonly string[] {
    return headers.get(name) ?? [];
}

export function getHeader(headers: HeaderMap, name: string): string | null {
    const values = getHeaderValues(headers, name);
    return values.length > 0 ? values.join(", ") : null;
}

export function splitDirectives(value: string): string[] {
    return value.split(/[;,]/).map((part) => part.trim().toLowerCase()).filter(Boolean);
}
