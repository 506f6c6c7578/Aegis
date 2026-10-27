import { isIP } from "node:net";
import { normalizeHostname } from "@/domain/domain/hostname";
import { isSameOrSubdomain } from "@/domain/domain/input";

const maxLocationLength = 2048;
const allowedProtocols = new Set(["http:", "https:"]);

export type RedirectRefusal =
    | "invalid-location"
    | "unsupported-scheme"
    | "credentials"
    | "port"
    | "ip-literal"
    | "invalid-host"
    | "out-of-scope";

export type RedirectDecision = { allowed: true; url: URL } | { allowed: false; reason: RedirectRefusal; destination: URL | null };

function parseLocation(location: string, current: URL): URL | null {
    if (!location || location.length > maxLocationLength) return null;
    try {
        return new URL(location, current);
    } catch {
        return null;
    }
}

function refuse(reason: RedirectRefusal, destination: URL | null): RedirectDecision {
    return { allowed: false, reason, destination };
}

export function evaluateRedirect(location: string, current: URL, scope: string): RedirectDecision {
    const url = parseLocation(location, current);
    if (!url) return refuse("invalid-location", null);
    if (!allowedProtocols.has(url.protocol)) return refuse("unsupported-scheme", null);
    if (url.username || url.password) return refuse("credentials", null);
    if (url.port) return refuse("port", url);
    if (isIP(url.hostname.replace(/^\[|\]$/g, ""))) return refuse("ip-literal", url);

    const normalized = normalizeHostname(url.hostname);
    if (!normalized.ok) return refuse("invalid-host", url);
    if (!isSameOrSubdomain(normalized.hostname.ascii, scope)) return refuse("out-of-scope", url);

    url.hostname = normalized.hostname.ascii;
    return { allowed: true, url };
}
