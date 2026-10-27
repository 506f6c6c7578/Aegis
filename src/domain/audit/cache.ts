import { type CheckDefinition, createCheck, getHeader, splitDirectives } from "@/domain/audit/checks";
import type { AuditCheck, CookieView, HeaderMap } from "@/domain/audit/model";
import { references } from "@/domain/audit/references";

const definitions = {
    cacheControl: { id: "cache-control", category: "cache", title: "Règles de cache", reference: references.cacheControl },
    disclosure: { id: "server-disclosure", category: "cache", title: "Informations sur le serveur", reference: references.server }
} as const satisfies Record<string, CheckDefinition>;

export const cacheCheckIds = { cacheControl: definitions.cacheControl.id, disclosure: definitions.disclosure.id } as const;

const disclosureHeaders = ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"];

function describeCacheHeaders(headers: HeaderMap): string | null {
    const values = ["cache-control", "pragma", "expires"].flatMap((name) => {
        const value = getHeader(headers, name);
        return value ? [`${name}: ${value}`] : [];
    });
    return values.length > 0 ? values.join(" · ") : null;
}

function analyzeCacheControl(headers: HeaderMap, cookies: readonly CookieView[]): AuditCheck {
    const value = getHeader(headers, "cache-control");
    const directives = value ? splitDirectives(value) : [];
    const observed = describeCacheHeaders(headers);
    const restricted = directives.includes("no-store") || directives.includes("private");
    if (cookies.some(({ sensitive }) => sensitive) && !restricted) {
        return createCheck(definitions.cacheControl, {
            status: directives.includes("public") ? "fail" : "warning",
            priority: "medium",
            explanation: "La page dépose des cookies sensibles mais peut être conservée par un cache partagé, qui risque de la servir à d'autres visiteurs.",
            recommendation: "Envoie Cache-Control: private, no-store sur les réponses personnalisées.",
            observed
        });
    }
    if (!value) {
        return createCheck(definitions.cacheControl, {
            status: "warning",
            priority: "low",
            explanation: getHeader(headers, "pragma") || getHeader(headers, "expires")
                ? "Seuls les anciens en-têtes Pragma ou Expires sont présents : Cache-Control les remplace."
                : "Sans Cache-Control, chaque cache applique ses propres heuristiques.",
            recommendation: "Définis explicitement Cache-Control, par exemple no-cache pour une page HTML.",
            observed
        });
    }
    return createCheck(definitions.cacheControl, { status: "pass", priority: "low", explanation: "La politique de cache est explicite.", observed });
}

function analyzeDisclosure(headers: HeaderMap): AuditCheck {
    const server = getHeader(headers, "server");
    const disclosed = disclosureHeaders.flatMap((name) => {
        const value = getHeader(headers, name);
        return value ? [`${name}: ${value}`] : [];
    });
    if (server && /\d/.test(server)) disclosed.unshift(`server: ${server}`);
    return disclosed.length === 0
        ? createCheck(definitions.disclosure, {
            status: "pass",
            priority: "info",
            explanation: server ? "L'en-tête Server ne précise pas de version." : "Aucune information technique n'est exposée.",
            observed: server ? `server: ${server}` : null
        })
        : createCheck(definitions.disclosure, {
            status: "warning",
            priority: "low",
            explanation: "Les versions logicielles exposées facilitent la recherche de vulnérabilités connues. Ce n'est pas une faille en soi.",
            recommendation: "Masque les numéros de version (par exemple server_tokens off avec Nginx) et retire X-Powered-By.",
            observed: disclosed.join(" · ")
        });
}

export function analyzeCache(headers: HeaderMap, cookies: readonly CookieView[]): AuditCheck[] {
    return [analyzeCacheControl(headers, cookies), analyzeDisclosure(headers)];
}
