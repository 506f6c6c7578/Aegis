import { type CheckDefinition, type CheckOutcome, createCheck, getHeaderValues, maskObserved } from "@/domain/audit/checks";
import type { AuditCheck, CheckStatus, CspDirectiveView, CspPolicyView, HeaderMap } from "@/domain/audit/model";
import { references } from "@/domain/audit/references";

const maxPolicies = 4;
const maxDirectives = 40;
const maxSources = 40;
const maxMetaPolicyLength = 8_192;
const directiveNamePattern = /^[a-z-]{1,40}$/;
const metaTagPattern = /<meta\b[^>]*>/gi;
const attributePattern = /([a-z-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/gi;
const ignoredMetaDirectives = new Set(["frame-ancestors", "report-uri", "report-to", "sandbox"]);

const definitions = {
    present: { id: "csp-present", category: "csp", title: "Présence d'une CSP", reference: references.csp },
    defaultSrc: { id: "csp-default-src", category: "csp", title: "default-src", reference: references.csp },
    scriptSrc: { id: "csp-script-src", category: "csp", title: "script-src", reference: references.csp },
    objectSrc: { id: "csp-object-src", category: "csp", title: "object-src", reference: references.csp },
    baseUri: { id: "csp-base-uri", category: "csp", title: "base-uri", reference: references.csp },
    formAction: { id: "csp-form-action", category: "csp", title: "form-action", reference: references.csp },
    styleSrc: { id: "csp-style-src", category: "csp", title: "Styles en ligne", reference: references.csp },
    broadSources: { id: "csp-broad-sources", category: "csp", title: "Sources trop larges", reference: references.csp }
} as const satisfies Record<string, CheckDefinition>;

export const cspCheckIds = { present: definitions.present.id } as const;

const fetchDirectives = ["child-src", "connect-src", "font-src", "frame-src", "img-src", "manifest-src", "media-src", "style-src", "worker-src"];
const broadSources = new Set(["*", "http:", "https:"]);
const scriptBroadSources = new Set(["*", "http:", "https:", "data:", "blob:"]);
const statusRank: Record<CheckStatus, number> = { "pass": 0, "warning": 1, "fail": 2, "not-applicable": 3 };

function normalizeSource(source: string): string {
    if (/^'nonce-/i.test(source)) return "'nonce-…'";
    if (/^'sha(?:256|384|512)-/i.test(source)) return `'${source.slice(1, 7).toLowerCase()}${source.slice(7)}`;
    return maskObserved(source.toLowerCase());
}

function parsePolicy(policy: string, mode: CspPolicyView["mode"], source: CspPolicyView["source"]): CspPolicyView | null {
    const directives: CspDirectiveView[] = [];
    for (const part of policy.split(";")) {
        const [rawName = "", ...sources] = part.trim().split(/\s+/);
        const name = rawName.toLowerCase();
        if (!directiveNamePattern.test(name) || directives.some((directive) => directive.name === name)) continue;
        if (source === "meta" && ignoredMetaDirectives.has(name)) continue;
        directives.push({ name, sources: sources.slice(0, maxSources).map(normalizeSource) });
        if (directives.length === maxDirectives) break;
    }
    return directives.length > 0 ? { mode, source, directives } : null;
}

function parseHeader(headers: HeaderMap, name: string, mode: CspPolicyView["mode"]): CspPolicyView[] {
    return getHeaderValues(headers, name)
        .flatMap((value) => value.split(","))
        .map((policy) => parsePolicy(policy, mode, "header"))
        .filter((policy) => policy !== null);
}

function decodeEntities(value: string): string {
    return value.replace(/&(?:quot|#34|#x22);/gi, "\"").replace(/&(?:apos|#39|#x27);/gi, "'").replace(/&(?:amp|#38|#x26);/gi, "&");
}

function readAttributes(tag: string): Map<string, string> {
    const attributes = new Map<string, string>();
    for (const [, name = "", doubleQuoted, singleQuoted, bare] of tag.matchAll(attributePattern)) {
        attributes.set(name.toLowerCase(), decodeEntities(doubleQuoted ?? singleQuoted ?? bare ?? ""));
    }
    return attributes;
}

export function extractMetaPolicies(html: string): string[] {
    const headEnd = html.toLowerCase().indexOf("</head>");
    const head = headEnd === -1 ? html : html.slice(0, headEnd);
    return Array.from(head.matchAll(metaTagPattern), ([tag]) => readAttributes(tag))
        .filter((attributes) => attributes.get("http-equiv")?.toLowerCase() === "content-security-policy")
        .map((attributes) => attributes.get("content")?.trim().slice(0, maxMetaPolicyLength) ?? "")
        .filter(Boolean)
        .slice(0, maxPolicies);
}

export function parseContentSecurityPolicies(headers: HeaderMap, metaPolicies: readonly string[] = []): CspPolicyView[] {
    return [
        ...parseHeader(headers, "content-security-policy", "enforce"),
        ...metaPolicies.map((policy) => parsePolicy(policy, "enforce", "meta")).filter((policy) => policy !== null),
        ...parseHeader(headers, "content-security-policy-report-only", "report-only")
    ].slice(0, maxPolicies);
}

function getDirective(policy: CspPolicyView, name: string): string[] | null {
    return policy.directives.find((directive) => directive.name === name)?.sources ?? null;
}

function getEffectiveSources(policy: CspPolicyView, name: string): string[] | null {
    return getDirective(policy, name) ?? getDirective(policy, "default-src");
}

function describe(name: string, sources: readonly string[] | null): string | null {
    return sources ? `${name} ${sources.join(" ") || "(vide)"}`.trim() : null;
}

function bestOutcome(policies: readonly CspPolicyView[], evaluate: (policy: CspPolicyView) => CheckOutcome): CheckOutcome {
    return policies
        .map(evaluate)
        .reduce((best, outcome) => (statusRank[outcome.status] < statusRank[best.status] ? outcome : best));
}

function evaluateScriptSources(policy: CspPolicyView): CheckOutcome {
    const sources = getEffectiveSources(policy, "script-src");
    const observed = describe("script-src", sources);
    if (!sources) {
        return {
            status: "fail",
            priority: "high",
            explanation: "Ni script-src ni default-src ne sont définis : n'importe quel script peut s'exécuter.",
            recommendation: "Définis script-src 'self', complété par des empreintes ou des nonces pour les scripts en ligne."
        };
    }
    const hasNonceOrHash = sources.some((source) => /^'(?:nonce|sha256|sha384|sha512)-/.test(source));
    const strictDynamic = sources.includes("'strict-dynamic'");
    const broad = sources.filter((source) => scriptBroadSources.has(source));
    if (sources.includes("'unsafe-inline'") && !hasNonceOrHash) {
        return {
            status: "fail",
            priority: "high",
            explanation: "'unsafe-inline' autorise tous les scripts en ligne : la CSP ne protège plus contre les injections de scripts (XSS).",
            recommendation: "Retire 'unsafe-inline' et autorise les scripts en ligne nécessaires par empreinte (sha256-…) ou par nonce.",
            observed
        };
    }
    if (broad.length > 0 && !strictDynamic) {
        return {
            status: "fail",
            priority: "high",
            explanation: `La source ${broad.join(", ")} autorise des scripts provenant de presque n'importe où.`,
            recommendation: "Limite script-src à 'self' et aux origines strictement nécessaires.",
            observed
        };
    }
    if (sources.includes("'unsafe-eval'")) {
        return {
            status: "warning",
            priority: "medium",
            explanation: "'unsafe-eval' autorise eval() et les constructions équivalentes, une porte d'entrée fréquente pour les injections.",
            recommendation: "Retire 'unsafe-eval' après avoir remplacé les usages d'eval() et de new Function().",
            observed
        };
    }
    return { status: "pass", priority: "high", explanation: "Les scripts autorisés sont limités à des sources précises.", observed };
}

function evaluateObjectSources(policy: CspPolicyView): CheckOutcome {
    const sources = getEffectiveSources(policy, "object-src");
    return sources?.length === 1 && sources[0] === "'none'"
        ? { status: "pass", priority: "medium", explanation: "Les plugins (object, embed) sont interdits.", observed: describe("object-src", sources) }
        : {
            status: "warning",
            priority: "medium",
            explanation: "Les éléments object et embed restent autorisés alors qu'ils ne sont presque plus jamais nécessaires.",
            recommendation: "Ajoute object-src 'none'.",
            observed: describe("object-src", sources)
        };
}

function evaluateBaseUri(policy: CspPolicyView): CheckOutcome {
    const sources = getDirective(policy, "base-uri");
    if (!sources) {
        return {
            status: "warning",
            priority: "medium",
            explanation: "base-uri n'hérite pas de default-src : une injection de balise base pourrait détourner les URL relatives.",
            recommendation: "Ajoute base-uri 'none' ou base-uri 'self'."
        };
    }
    const strict = sources.length === 1 && (sources[0] === "'none'" || sources[0] === "'self'");
    return strict
        ? { status: "pass", priority: "medium", explanation: "L'URL de base du document est verrouillée.", observed: describe("base-uri", sources) }
        : {
            status: "warning",
            priority: "low",
            explanation: "base-uri autorise d'autres origines que le site lui-même.",
            recommendation: "Restreins base-uri à 'self' ou 'none'.",
            observed: describe("base-uri", sources)
        };
}

function evaluateFormAction(policy: CspPolicyView): CheckOutcome {
    const sources = getDirective(policy, "form-action");
    if (!sources) {
        return {
            status: "warning",
            priority: "low",
            explanation: "form-action n'hérite pas de default-src : un formulaire injecté pourrait envoyer des données vers un autre site.",
            recommendation: "Ajoute form-action 'self'."
        };
    }
    return sources.some((source) => broadSources.has(source))
        ? {
            status: "warning",
            priority: "low",
            explanation: "form-action autorise l'envoi de formulaires vers presque n'importe quelle origine.",
            recommendation: "Restreins form-action à 'self' et aux destinations nécessaires.",
            observed: describe("form-action", sources)
        }
        : { status: "pass", priority: "low", explanation: "Les destinations des formulaires sont limitées.", observed: describe("form-action", sources) };
}

function evaluateDefaultSources(policy: CspPolicyView): CheckOutcome {
    const sources = getDirective(policy, "default-src");
    if (!sources) {
        return {
            status: "warning",
            priority: "medium",
            explanation: "Sans default-src, toute directive non définie reste sans restriction : il n'y a pas de repli cohérent.",
            recommendation: "Ajoute default-src 'self' (ou 'none') puis ouvre uniquement les directives nécessaires."
        };
    }
    return sources.some((source) => broadSources.has(source))
        ? {
            status: "fail",
            priority: "medium",
            explanation: "default-src autorise presque n'importe quelle origine : le repli ne restreint rien.",
            recommendation: "Remplace la source trop large par 'self'.",
            observed: describe("default-src", sources)
        }
        : { status: "pass", priority: "medium", explanation: "default-src fournit un repli restrictif aux autres directives.", observed: describe("default-src", sources) };
}

function evaluateStyleSources(policy: CspPolicyView): CheckOutcome {
    const sources = getEffectiveSources(policy, "style-src");
    const observed = describe("style-src", sources);
    return sources?.includes("'unsafe-inline'")
        ? {
            status: "warning",
            priority: "low",
            explanation: "'unsafe-inline' dans style-src permet d'injecter des styles, utilisables pour masquer ou imiter du contenu.",
            recommendation: "Autorise les styles en ligne par empreinte ou par nonce lorsque c'est possible.",
            observed
        }
        : { status: "pass", priority: "low", explanation: "Les styles en ligne ne sont pas autorisés sans empreinte ni nonce.", observed };
}

function evaluateBroadSources(policy: CspPolicyView): CheckOutcome {
    const broad = policy.directives.filter(({ name, sources }) => fetchDirectives.includes(name) && sources.some((source) => broadSources.has(source)));
    return broad.length > 0
        ? {
            status: "warning",
            priority: "medium",
            explanation: `Ces directives acceptent presque n'importe quelle origine : ${broad.map(({ name }) => name).join(", ")}.`,
            recommendation: "Remplace *, http: et https: par la liste des origines réellement utilisées.",
            observed: broad.map(({ name, sources }) => describe(name, sources)).join(" ; ")
        }
        : { status: "pass", priority: "medium", explanation: "Aucune directive de chargement n'accepte une source générique." };
}

const evaluations: readonly [CheckDefinition, (policy: CspPolicyView) => CheckOutcome][] = [
    [definitions.defaultSrc, evaluateDefaultSources],
    [definitions.scriptSrc, evaluateScriptSources],
    [definitions.objectSrc, evaluateObjectSources],
    [definitions.baseUri, evaluateBaseUri],
    [definitions.formAction, evaluateFormAction],
    [definitions.styleSrc, evaluateStyleSources],
    [definitions.broadSources, evaluateBroadSources]
];

function analyzePresence(policies: readonly CspPolicyView[], enforced: readonly CspPolicyView[]): AuditCheck {
    if (enforced.length > 0) {
        return createCheck(definitions.present, {
            status: "pass",
            priority: "high",
            explanation: enforced.length > 1 ? `${enforced.length} politiques sont appliquées et se cumulent.` : "Une politique de sécurité du contenu est appliquée.",
            observed: enforced.map(({ source }) => (source === "meta" ? "balise meta" : "en-tête HTTP")).join(", ")
        });
    }
    return policies.length > 0
        ? createCheck(definitions.present, {
            status: "warning",
            priority: "high",
            explanation: "La CSP est seulement en mode Report-Only : les violations sont signalées mais rien n'est bloqué.",
            recommendation: "Une fois les rapports analysés, publie la politique dans l'en-tête Content-Security-Policy."
        })
        : createCheck(definitions.present, {
            status: "fail",
            priority: "high",
            explanation: "Aucune Content Security Policy n'est envoyée : le navigateur n'a aucune limite sur les scripts et ressources chargés.",
            recommendation: "Commence par default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none', puis ajuste."
        });
}

export function analyzeCsp(policies: readonly CspPolicyView[]): AuditCheck[] {
    const enforced = policies.filter(({ mode }) => mode === "enforce");
    const presence = analyzePresence(policies, enforced);
    if (enforced.length === 0) {
        return [
            presence,
            ...evaluations.map(([definition]) => createCheck(definition, {
                status: "not-applicable",
                priority: "medium",
                explanation: "Aucune CSP n'est appliquée : cette directive ne peut pas être évaluée."
            }))
        ];
    }
    return [presence, ...evaluations.map(([definition, evaluate]) => createCheck(definition, bestOutcome(enforced, evaluate)))];
}

export function findFrameAncestors(policies: readonly CspPolicyView[]): string[] | null {
    const policy = policies.find((candidate) => candidate.mode === "enforce" && getDirective(candidate, "frame-ancestors"));
    return policy ? getDirective(policy, "frame-ancestors") : null;
}
