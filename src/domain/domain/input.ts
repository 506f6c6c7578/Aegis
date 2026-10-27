export const hostnameLimits = {
    inputMaxLength: 253,
    asciiMaxLength: 239,
    labelMaxLength: 63
} as const;

export type HostnameError =
    | "empty"
    | "too-long"
    | "url"
    | "credentials"
    | "wildcard"
    | "path"
    | "port"
    | "ip-address"
    | "invalid-characters"
    | "invalid-label"
    | "single-label"
    | "special-use"
    | "not-public"
    | "public-suffix";

export const hostnameErrorMessages: Record<HostnameError, string> = {
    "empty": "Saisis un nom de domaine.",
    "too-long": "Ce nom de domaine est trop long.",
    "url": "Saisis uniquement le nom de domaine, sans protocole (par exemple exemple.fr).",
    "credentials": "Les identifiants ne sont pas acceptés : saisis uniquement le nom de domaine.",
    "wildcard": "Les domaines génériques (*) ne sont pas acceptés.",
    "path": "Saisis uniquement le nom de domaine, sans chemin ni paramètres.",
    "port": "Le port ne peut pas être choisi : Aegis analyse toujours le port 443.",
    "ip-address": "Les adresses IP ne sont pas acceptées : saisis un nom de domaine.",
    "invalid-characters": "Ce nom de domaine contient des caractères non autorisés.",
    "invalid-label": "Ce nom de domaine n'est pas valide.",
    "single-label": "Saisis un nom de domaine complet, par exemple exemple.fr.",
    "special-use": "Ce domaine est réservé (local, interne ou de test) et ne peut pas être analysé.",
    "not-public": "Ce domaine n'appartient pas à une extension publique.",
    "public-suffix": "Ce nom correspond à une extension publique, pas à un domaine enregistrable."
};

const schemePattern = /^[a-z][a-z0-9+.-]*:\/\//i;
const ipv4Pattern = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const bracketedPattern = /^\[.*\]$/;
const allowedCharacters = /^[\p{L}\p{M}\p{N}.-]+$/u;

export function detectHostnameShapeError(input: string): HostnameError | null {
    if (!input) return "empty";
    if (input.length > hostnameLimits.inputMaxLength) return "too-long";
    if (schemePattern.test(input) || input.startsWith("//") || input.includes("://")) return "url";
    if (input.includes("@")) return "credentials";
    if (input.includes("*")) return "wildcard";
    if (/[/?#\\]/.test(input)) return "path";
    if (ipv4Pattern.test(input) || bracketedPattern.test(input) || (input.match(/:/g)?.length ?? 0) > 1) return "ip-address";
    if (input.includes(":")) return "port";
    if (!allowedCharacters.test(input)) return "invalid-characters";
    if (!input.replace(/\.$/, "").includes(".")) return "single-label";
    return null;
}

export function isSameOrSubdomain(hostname: string, domain: string): boolean {
    return hostname === domain || hostname.endsWith(`.${domain}`);
}
