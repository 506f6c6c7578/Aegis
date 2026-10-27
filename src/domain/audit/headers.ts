import { type CheckDefinition, createCheck, getHeader, splitDirectives } from "@/domain/audit/checks";
import { findFrameAncestors } from "@/domain/audit/csp";
import type { AuditCheck, CspPolicyView, HeaderMap } from "@/domain/audit/model";
import { references } from "@/domain/audit/references";

const definitions = {
    contentType: { id: "x-content-type-options", category: "headers", title: "X-Content-Type-Options", reference: references.contentTypeOptions },
    referrer: { id: "referrer-policy", category: "headers", title: "Referrer-Policy", reference: references.referrerPolicy },
    permissions: { id: "permissions-policy", category: "headers", title: "Permissions-Policy", reference: references.permissionsPolicy },
    opener: { id: "cross-origin-opener-policy", category: "headers", title: "Cross-Origin-Opener-Policy", reference: references.openerPolicy },
    resource: { id: "cross-origin-resource-policy", category: "headers", title: "Cross-Origin-Resource-Policy", reference: references.resourcePolicy },
    embedder: { id: "cross-origin-embedder-policy", category: "headers", title: "Cross-Origin-Embedder-Policy", reference: references.embedderPolicy },
    framing: { id: "framing", category: "headers", title: "Intégration en cadre (frame-ancestors)", reference: references.frameAncestors }
} as const satisfies Record<string, CheckDefinition>;

export const headerCheckIds = {
    contentType: definitions.contentType.id,
    referrer: definitions.referrer.id,
    permissions: definitions.permissions.id,
    opener: definitions.opener.id,
    resource: definitions.resource.id,
    embedder: definitions.embedder.id,
    framing: definitions.framing.id
} as const;

const strictReferrerPolicies = new Set(["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"]);
const permissiveReferrerPolicies = new Set(["origin", "origin-when-cross-origin", "no-referrer-when-downgrade"]);

function analyzeContentTypeOptions(headers: HeaderMap): AuditCheck {
    const value = getHeader(headers, "x-content-type-options");
    return value?.trim().toLowerCase() === "nosniff"
        ? createCheck(definitions.contentType, { status: "pass", priority: "medium", explanation: "Le navigateur respecte le type MIME déclaré.", observed: value })
        : createCheck(definitions.contentType, {
            status: "warning",
            priority: "medium",
            explanation: "Sans nosniff, le navigateur peut deviner le type d'un fichier et exécuter un contenu prévu comme inerte.",
            recommendation: "Ajoute X-Content-Type-Options: nosniff à toutes les réponses.",
            observed: value
        });
}

function analyzeReferrerPolicy(headers: HeaderMap): AuditCheck {
    const value = getHeader(headers, "referrer-policy");
    const policy = value ? splitDirectives(value).filter((token) => strictReferrerPolicies.has(token) || permissiveReferrerPolicies.has(token) || token === "unsafe-url").at(-1) : undefined;
    if (policy && strictReferrerPolicies.has(policy)) {
        return createCheck(definitions.referrer, { status: "pass", priority: "low", explanation: "Les adresses complètes ne sont pas transmises aux autres sites.", observed: value });
    }
    if (policy === "unsafe-url") {
        return createCheck(definitions.referrer, {
            status: "fail",
            priority: "medium",
            explanation: "unsafe-url transmet l'adresse complète, paramètres compris, à tous les sites, même en HTTP.",
            recommendation: "Utilise Referrer-Policy: strict-origin-when-cross-origin.",
            observed: value
        });
    }
    return createCheck(definitions.referrer, {
        status: "warning",
        priority: "low",
        explanation: policy
            ? "La politique choisie transmet plus d'informations que nécessaire aux autres sites."
            : "Aucune politique valide n'est définie : le comportement dépend du navigateur.",
        recommendation: "Définis explicitement Referrer-Policy: strict-origin-when-cross-origin.",
        observed: value
    });
}

function analyzePermissionsPolicy(headers: HeaderMap): AuditCheck {
    const value = getHeader(headers, "permissions-policy");
    if (value?.trim()) {
        return createCheck(definitions.permissions, { status: "pass", priority: "low", explanation: "Les fonctionnalités sensibles du navigateur sont encadrées.", observed: value });
    }
    const legacy = getHeader(headers, "feature-policy");
    return createCheck(definitions.permissions, {
        status: "warning",
        priority: "low",
        explanation: legacy
            ? "Seul l'ancien en-tête Feature-Policy est présent ; les navigateurs actuels utilisent Permissions-Policy."
            : "Aucune restriction n'est posée sur la caméra, le micro, la géolocalisation ou les autres fonctionnalités du navigateur.",
        recommendation: "Désactive les fonctionnalités inutilisées, par exemple Permissions-Policy: camera=(), microphone=(), geolocation=().",
        observed: legacy
    });
}

function analyzeOpenerPolicy(headers: HeaderMap): AuditCheck {
    const value = getHeader(headers, "cross-origin-opener-policy");
    const policy = value?.split(";")[0]?.trim().toLowerCase();
    return policy && ["same-origin", "same-origin-allow-popups", "noopener-allow-popups"].includes(policy)
        ? createCheck(definitions.opener, { status: "pass", priority: "medium", explanation: "La page est isolée des fenêtres ouvertes par d'autres origines.", observed: value })
        : createCheck(definitions.opener, {
            status: "warning",
            priority: "low",
            explanation: "Une fenêtre d'une autre origine peut conserver une référence vers cette page.",
            recommendation: "Ajoute Cross-Origin-Opener-Policy: same-origin, ou same-origin-allow-popups si des fenêtres de paiement ou d'authentification sont utilisées.",
            observed: value
        });
}

function analyzeResourcePolicy(headers: HeaderMap): AuditCheck {
    const value = getHeader(headers, "cross-origin-resource-policy");
    const policy = value?.trim().toLowerCase();
    if (policy === "same-origin" || policy === "same-site") {
        return createCheck(definitions.resource, { status: "pass", priority: "low", explanation: "Les autres origines ne peuvent pas intégrer cette ressource.", observed: value });
    }
    return policy === "cross-origin"
        ? createCheck(definitions.resource, {
            status: "warning",
            priority: "info",
            explanation: "cross-origin autorise toutes les origines à intégrer la ressource : un choix acceptable pour un contenu public.",
            observed: value
        })
        : createCheck(definitions.resource, {
            status: "warning",
            priority: "low",
            explanation: "Rien n'empêche une autre origine de charger cette ressource, ce qui facilite certaines attaques par canal auxiliaire.",
            recommendation: "Ajoute Cross-Origin-Resource-Policy: same-origin.",
            observed: value
        });
}

function analyzeEmbedderPolicy(headers: HeaderMap): AuditCheck {
    const value = getHeader(headers, "cross-origin-embedder-policy");
    const policy = value?.split(";")[0]?.trim().toLowerCase();
    return policy === "require-corp" || policy === "credentialless"
        ? createCheck(definitions.embedder, { status: "pass", priority: "info", explanation: "La page exige l'accord explicite des ressources qu'elle intègre.", observed: value })
        : createCheck(definitions.embedder, {
            status: "not-applicable",
            priority: "info",
            explanation: "Facultatif : utile seulement pour activer l'isolation entre origines (SharedArrayBuffer, mesures précises).",
            observed: value
        });
}

function analyzeFraming(headers: HeaderMap, policies: readonly CspPolicyView[]): AuditCheck {
    const frameAncestors = findFrameAncestors(policies);
    const frameOptions = getHeader(headers, "x-frame-options");
    if (frameAncestors) {
        const permissive = frameAncestors.some((source) => source === "*" || source === "https:" || source === "http:");
        return permissive
            ? createCheck(definitions.framing, {
                status: "fail",
                priority: "medium",
                explanation: "frame-ancestors autorise presque n'importe quel site à intégrer la page.",
                recommendation: "Utilise frame-ancestors 'none', ou 'self' si la page doit s'intégrer à ton propre site.",
                observed: `frame-ancestors ${frameAncestors.join(" ")}`
            })
            : createCheck(definitions.framing, {
                status: "pass",
                priority: "medium",
                explanation: frameOptions
                    ? "frame-ancestors limite l'intégration de la page. X-Frame-Options est conservé pour les anciens navigateurs."
                    : "frame-ancestors limite l'intégration de la page dans un cadre.",
                observed: `frame-ancestors ${frameAncestors.join(" ")}`
            });
    }
    const option = frameOptions?.trim().toUpperCase();
    if (option === "DENY" || option === "SAMEORIGIN") {
        return createCheck(definitions.framing, {
            status: "pass",
            priority: "medium",
            explanation: "X-Frame-Options empêche l'intégration de la page sur d'autres sites.",
            recommendation: "Ajoute aussi frame-ancestors dans la CSP : X-Frame-Options n'est conservé que pour compatibilité.",
            observed: `X-Frame-Options: ${frameOptions}`
        });
    }
    return createCheck(definitions.framing, {
        status: "fail",
        priority: "medium",
        explanation: frameOptions
            ? "La valeur de X-Frame-Options n'est pas reconnue par les navigateurs actuels : la page peut être intégrée dans un cadre (clickjacking)."
            : "Aucune protection n'empêche un autre site d'intégrer la page dans un cadre invisible (clickjacking).",
        recommendation: "Ajoute frame-ancestors 'none' à la CSP, et X-Frame-Options: DENY pour les anciens navigateurs.",
        observed: frameOptions
    });
}

export function analyzeHeaders(headers: HeaderMap, policies: readonly CspPolicyView[]): AuditCheck[] {
    return [
        analyzeContentTypeOptions(headers),
        analyzeReferrerPolicy(headers),
        analyzePermissionsPolicy(headers),
        analyzeOpenerPolicy(headers),
        analyzeResourcePolicy(headers),
        analyzeEmbedderPolicy(headers),
        analyzeFraming(headers, policies)
    ];
}
