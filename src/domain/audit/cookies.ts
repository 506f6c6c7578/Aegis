import { type CheckDefinition, createCheck, getHeaderValues } from "@/domain/audit/checks";
import type { AuditCheck, CookieView, HeaderMap, SameSite } from "@/domain/audit/model";
import { references } from "@/domain/audit/references";

const maxCookies = 50;
const maxNameLength = 64;
const maxAttributeLength = 120;
const longLifetimeSeconds = 31_536_000;
const sensitiveNamePattern = /sess|sid|auth|token|jwt|csrf|xsrf|login|remember|account|identity|refresh|access/i;
const scriptReadableNamePattern = /csrf|xsrf/i;
const sameSiteValues: Readonly<Record<string, SameSite>> = { strict: "Strict", lax: "Lax", none: "None" };

const definitions = {
    secure: { id: "cookies-secure", category: "cookies", title: "Attribut Secure", reference: references.setCookie },
    httpOnly: { id: "cookies-httponly", category: "cookies", title: "Attribut HttpOnly", reference: references.setCookie },
    sameSite: { id: "cookies-samesite", category: "cookies", title: "Attribut SameSite", reference: references.setCookie },
    scope: { id: "cookies-scope", category: "cookies", title: "Portée (Domain et préfixes)", reference: references.cookies },
    lifetime: { id: "cookies-lifetime", category: "cookies", title: "Durée de vie", reference: references.cookies }
} as const satisfies Record<string, CheckDefinition>;

function sanitize(value: string, maxLength: number): string {
    const clean = value.replace(/\p{Cc}/gu, "").trim();
    return clean.length > maxLength ? `${clean.slice(0, maxLength)}…` : clean;
}

function readName(pair: string): string {
    const separator = pair.indexOf("=");
    return sanitize(separator === -1 ? "" : pair.slice(0, separator), maxNameLength);
}

function readLifetime(maxAge: string | undefined, expires: string | undefined, now: number): CookieView["lifetime"] | null {
    if (maxAge !== undefined && /^-?\d{1,12}$/.test(maxAge)) {
        const seconds = Number(maxAge);
        return seconds > 0 ? { kind: "persistent", seconds } : null;
    }
    const expiresAt = expires ? Date.parse(expires) : Number.NaN;
    if (Number.isNaN(expiresAt)) return { kind: "session" };
    return expiresAt > now ? { kind: "persistent", seconds: Math.round((expiresAt - now) / 1_000) } : null;
}

function readPrefix(name: string): CookieView["prefix"] {
    if (name.toLowerCase().startsWith("__host-")) return "__Host-";
    return name.toLowerCase().startsWith("__secure-") ? "__Secure-" : null;
}

export function parseSetCookie(header: string, now: number): CookieView | null {
    const [pair = "", ...parts] = header.split(";");
    const attributes = new Map<string, string>();
    for (const part of parts) {
        const separator = part.indexOf("=");
        const key = (separator === -1 ? part : part.slice(0, separator)).trim().toLowerCase();
        if (key && !attributes.has(key)) attributes.set(key, separator === -1 ? "" : sanitize(part.slice(separator + 1), maxAttributeLength));
    }
    const lifetime = readLifetime(attributes.get("max-age"), attributes.get("expires"), now);
    if (!lifetime) return null;
    const name = readName(pair);
    const prefix = readPrefix(name);
    return {
        name,
        secure: attributes.has("secure"),
        httpOnly: attributes.has("httponly"),
        sameSite: sameSiteValues[attributes.get("samesite")?.toLowerCase() ?? ""] ?? null,
        domain: attributes.get("domain")?.replace(/^\./, "").toLowerCase() || null,
        path: attributes.get("path") || null,
        lifetime,
        sensitive: prefix !== null || sensitiveNamePattern.test(name),
        prefix
    };
}

export function parseCookies(headers: HeaderMap, now: number): CookieView[] {
    const cookies = new Map<string, CookieView>();
    for (const header of getHeaderValues(headers, "set-cookie")) {
        const cookie = parseSetCookie(header, now);
        if (cookie) cookies.set(`${cookie.name}|${cookie.domain ?? ""}|${cookie.path ?? ""}`, cookie);
        if (cookies.size === maxCookies) break;
    }
    return [...cookies.values()];
}

function listNames(cookies: readonly CookieView[]): string {
    return cookies.map(({ name }) => name || "(sans nom)").join(", ");
}

function analyzeSecure(cookies: readonly CookieView[]): AuditCheck {
    const insecure = cookies.filter(({ secure }) => !secure);
    return insecure.length === 0
        ? createCheck(definitions.secure, { status: "pass", priority: "high", explanation: "Tous les cookies ne sont transmis qu'en HTTPS." })
        : createCheck(definitions.secure, {
            status: "fail",
            priority: insecure.some(({ sensitive }) => sensitive) ? "high" : "medium",
            explanation: "Ces cookies peuvent être envoyés en clair sur une connexion HTTP et interceptés.",
            recommendation: "Ajoute l'attribut Secure à chaque cookie.",
            observed: listNames(insecure)
        });
}

function analyzeHttpOnly(cookies: readonly CookieView[]): AuditCheck {
    const candidates = cookies.filter(({ name, sensitive }) => sensitive && !scriptReadableNamePattern.test(name));
    if (candidates.length === 0) {
        return createCheck(definitions.httpOnly, {
            status: "not-applicable",
            priority: "high",
            explanation: "Aucun cookie ne ressemble à un cookie de session ou d'authentification."
        });
    }
    const exposed = candidates.filter(({ httpOnly }) => !httpOnly);
    return exposed.length === 0
        ? createCheck(definitions.httpOnly, { status: "pass", priority: "high", explanation: "Les cookies sensibles sont inaccessibles aux scripts de la page." })
        : createCheck(definitions.httpOnly, {
            status: "fail",
            priority: "high",
            explanation: "Ces cookies, qui semblent liés à la session, sont lisibles par JavaScript : une faille XSS suffirait à les voler.",
            recommendation: "Ajoute l'attribut HttpOnly aux cookies de session et d'authentification.",
            observed: listNames(exposed)
        });
}

function analyzeSameSite(cookies: readonly CookieView[]): AuditCheck {
    const missing = cookies.filter(({ sameSite }) => sameSite === null);
    const crossSite = cookies.filter(({ sameSite, sensitive }) => sameSite === "None" && sensitive);
    if (crossSite.length > 0) {
        return createCheck(definitions.sameSite, {
            status: "warning",
            priority: "medium",
            explanation: "Ces cookies sensibles sont envoyés avec les requêtes provenant d'autres sites, ce qui expose aux attaques CSRF.",
            recommendation: "Utilise SameSite=Lax ou Strict, sauf besoin avéré d'un usage entre sites.",
            observed: listNames(crossSite)
        });
    }
    return missing.length === 0
        ? createCheck(definitions.sameSite, { status: "pass", priority: "medium", explanation: "Chaque cookie précise sa politique SameSite." })
        : createCheck(definitions.sameSite, {
            status: "warning",
            priority: "low",
            explanation: "Sans SameSite explicite, le comportement dépend du navigateur.",
            recommendation: "Définis SameSite=Lax (ou Strict pour les cookies de session).",
            observed: listNames(missing)
        });
}

function analyzeScope(cookies: readonly CookieView[]): AuditCheck {
    const shared = cookies.filter(({ sensitive, domain }) => sensitive && domain !== null);
    const unprefixed = cookies.filter(({ sensitive, prefix }) => sensitive && prefix === null);
    if (shared.length > 0) {
        return createCheck(definitions.scope, {
            status: "warning",
            priority: "low",
            explanation: "L'attribut Domain partage ces cookies sensibles avec tous les sous-domaines.",
            recommendation: "Retire Domain et utilise le préfixe __Host- pour limiter le cookie au nom d'hôte exact.",
            observed: listNames(shared)
        });
    }
    return unprefixed.length === 0
        ? createCheck(definitions.scope, { status: "pass", priority: "low", explanation: "Les cookies sensibles sont limités au nom d'hôte qui les dépose." })
        : createCheck(definitions.scope, {
            status: "warning",
            priority: "info",
            explanation: "Les préfixes __Host- ou __Secure- garantissent au navigateur que le cookie a été déposé de façon sûre.",
            recommendation: "Renomme les cookies de session avec le préfixe __Host-.",
            observed: listNames(unprefixed)
        });
}

function analyzeLifetime(cookies: readonly CookieView[]): AuditCheck {
    const long = cookies.filter(({ sensitive, lifetime }) => sensitive && lifetime.kind === "persistent" && lifetime.seconds > longLifetimeSeconds);
    return long.length === 0
        ? createCheck(definitions.lifetime, { status: "pass", priority: "low", explanation: "Aucun cookie sensible n'est conservé plus d'un an." })
        : createCheck(definitions.lifetime, {
            status: "warning",
            priority: "low",
            explanation: "Ces cookies sensibles restent valides plus d'un an : un vol de cookie resterait exploitable longtemps.",
            recommendation: "Réduis la durée de vie des cookies de session et renouvelle-les régulièrement.",
            observed: listNames(long)
        });
}

export function analyzeCookies(cookies: readonly CookieView[]): AuditCheck[] {
    if (cookies.length === 0) {
        return Object.values(definitions).map((definition) => createCheck(definition, {
            status: "not-applicable",
            priority: "medium",
            explanation: "La page d'accueil ne dépose aucun cookie."
        }));
    }
    return [analyzeSecure(cookies), analyzeHttpOnly(cookies), analyzeSameSite(cookies), analyzeScope(cookies), analyzeLifetime(cookies)];
}
