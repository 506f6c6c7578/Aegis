import type { DocumentationLink } from "@/domain/audit/model";

function mdn(label: string, path: string): DocumentationLink {
    return { label: `MDN : ${label}`, url: `https://developer.mozilla.org/fr/docs/Web/HTTP/${path}` };
}

function mdnHeader(name: string): DocumentationLink {
    return mdn(name, `Reference/Headers/${name}`);
}

export const references = {
    tls: { label: "MDN : TLS", url: "https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/TLS" },
    tlsConfiguration: { label: "Générateur de configuration TLS de Mozilla", url: "https://ssl-config.mozilla.org/" },
    redirections: mdn("Redirections", "Guides/Redirections"),
    cookies: mdn("Cookies", "Guides/Cookies"),
    setCookie: mdnHeader("Set-Cookie"),
    hsts: mdnHeader("Strict-Transport-Security"),
    csp: mdnHeader("Content-Security-Policy"),
    frameAncestors: mdn("frame-ancestors", "Reference/Headers/Content-Security-Policy/frame-ancestors"),
    contentTypeOptions: mdnHeader("X-Content-Type-Options"),
    referrerPolicy: mdnHeader("Referrer-Policy"),
    permissionsPolicy: mdnHeader("Permissions-Policy"),
    openerPolicy: mdnHeader("Cross-Origin-Opener-Policy"),
    resourcePolicy: mdnHeader("Cross-Origin-Resource-Policy"),
    embedderPolicy: mdnHeader("Cross-Origin-Embedder-Policy"),
    frameOptions: mdnHeader("X-Frame-Options"),
    cacheControl: mdnHeader("Cache-Control"),
    server: mdnHeader("Server")
} as const satisfies Record<string, DocumentationLink>;
