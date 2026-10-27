import { describe, expect, it } from "vitest";
import { sampleReport } from "@/data/sample-report";
import { categories } from "@/domain/audit/labels";
import { type AuditCheck, type CategoryId, categoryIds, type CheckStatus, type Priority } from "@/domain/audit/model";
import { getRecommendations } from "@/domain/audit/recommendations";
import { computeCategoryRatio, computeScore, summarize } from "@/domain/audit/score";
import { reportSchema } from "@/lib/validation/report";

function check(category: CategoryId, status: CheckStatus, priority: Priority, id = `${category}-${status}-${priority}`): AuditCheck {
    return { id, category, status, priority, title: id, explanation: "", recommendation: null, observed: null, reference: null };
}

const allCategories = new Set<CategoryId>(categoryIds);

describe("score", () => {
    it("additionne des poids de catégorie égaux à 100", () => {
        expect(Object.values(categories).reduce((total, { weight }) => total + weight, 0)).toBe(100);
    });

    it("donne 100 quand tout est conforme ou non applicable", () => {
        expect(computeScore([check("transport", "pass", "critical"), check("csp", "not-applicable", "high")], allCategories).value).toBe(100);
    });

    it("pondère chaque contrôle selon sa priorité", () => {
        expect(computeCategoryRatio([check("csp", "pass", "high"), check("csp", "fail", "low")])).toBeCloseTo(4 / 5);
        expect(computeCategoryRatio([check("csp", "warning", "medium")])).toBe(0.5);
        expect(computeCategoryRatio([check("csp", "fail", "info")])).toBe(1);
    });

    it("n'accorde aucun point à une catégorie non évaluée", () => {
        const score = computeScore([], new Set<CategoryId>(["transport"]));
        expect(score.value).toBe(25);
        expect(score.categories.find(({ id }) => id === "headers")).toMatchObject({ evaluated: false, earned: 0 });
    });

    it("compte les états", () => {
        expect(summarize([check("csp", "pass", "high"), check("tls", "fail", "low"), check("cache", "not-applicable", "low")]))
            .toEqual({ pass: 1, warning: 0, fail: 1, notApplicable: 1 });
    });
});

describe("getRecommendations", () => {
    it("classe par priorité puis place les problèmes avant les recommandations", () => {
        const ordered = getRecommendations([
            check("cache", "warning", "low", "a"),
            check("csp", "pass", "critical", "b"),
            check("csp", "warning", "high", "c"),
            check("transport", "fail", "critical", "d"),
            check("headers", "fail", "high", "e"),
            check("cookies", "warning", "info", "f")
        ]);
        expect(ordered.map(({ id }) => id)).toEqual(["d", "e", "c", "a", "f"]);
    });
});

describe("rapport fictif", () => {
    it("respecte le schéma partagé avec le client", () => {
        expect(reportSchema.safeParse(JSON.parse(JSON.stringify(sampleReport))).success).toBe(true);
    });

    it("produit un score explicable et cohérent avec ses catégories", () => {
        const total = sampleReport.score.categories.reduce((sum, { earned }) => sum + earned, 0);
        expect(sampleReport.score.value).toBe(Math.round(total));
        expect(sampleReport.score.value).toBeGreaterThan(0);
        expect(sampleReport.score.value).toBeLessThan(100);
    });

    it("n'expose aucune valeur de cookie", () => {
        expect(JSON.stringify(sampleReport)).not.toContain("valeur-fictive");
        expect(sampleReport.cookies.map(({ name }) => name)).toEqual(["session_id", "preferences"]);
    });

    it("donne à chaque contrôle un titre, une explication et, s'il échoue, une recommandation", () => {
        for (const item of sampleReport.checks) {
            expect(item.title).not.toBe("");
            expect(item.explanation).not.toBe("");
            if (item.status === "fail") expect(item.recommendation).not.toBeNull();
        }
        expect(new Set(sampleReport.checks.map(({ id }) => id)).size).toBe(sampleReport.checks.length);
    });
});
