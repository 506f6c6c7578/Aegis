import { type AuditCheck, priorities } from "@/domain/audit/model";

export function getRecommendations(checks: readonly AuditCheck[]): AuditCheck[] {
    return checks
        .filter(({ status }) => status === "fail" || status === "warning")
        .toSorted((first, second) =>
            priorities.indexOf(first.priority) - priorities.indexOf(second.priority)
            || Number(second.status === "fail") - Number(first.status === "fail"));
}
