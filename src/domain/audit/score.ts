import { categories } from "@/domain/audit/labels";
import { type AuditCheck, type AuditScore, type AuditSummary, type CategoryId, categoryIds, type CheckStatus, type Priority } from "@/domain/audit/model";

export const priorityWeights: Record<Priority, number> = { critical: 6, high: 4, medium: 2, low: 1, info: 0 };

export const statusCredits: Record<Exclude<CheckStatus, "not-applicable">, number> = { pass: 1, warning: 0.5, fail: 0 };

function roundToTenth(value: number): number {
    return Math.round(value * 10) / 10;
}

export function computeCategoryRatio(checks: readonly AuditCheck[]): number {
    let possible = 0;
    let earned = 0;
    for (const { status, priority } of checks) {
        if (status === "not-applicable") continue;
        possible += priorityWeights[priority];
        earned += priorityWeights[priority] * statusCredits[status];
    }
    return possible === 0 ? 1 : earned / possible;
}

export function computeScore(checks: readonly AuditCheck[], evaluated: ReadonlySet<CategoryId>): AuditScore {
    const scores = categoryIds.map((id) => {
        const { weight } = categories[id];
        const isEvaluated = evaluated.has(id);
        const ratio = computeCategoryRatio(checks.filter(({ category }) => category === id));
        return { id, weight, evaluated: isEvaluated, earned: isEvaluated ? roundToTenth(weight * ratio) : 0 };
    });
    return { value: Math.round(scores.reduce((total, { earned }) => total + earned, 0)), categories: scores };
}

export function summarize(checks: readonly AuditCheck[]): AuditSummary {
    const count = (status: CheckStatus) => checks.filter((check) => check.status === status).length;
    return { pass: count("pass"), warning: count("warning"), fail: count("fail"), notApplicable: count("not-applicable") };
}
