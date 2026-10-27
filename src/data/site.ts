import { robotsDirective } from "../lib/http/security-headers.ts";

export interface NavigationLink {
    label: string;
    href: string;
    section?: string;
}

export const site = {
    url: "https://aegis.paulviandier.com",
    lang: "fr",
    locale: "fr_FR",
    name: "Aegis",
    tagline: "Analyse la posture de sécurité de tes domaines.",
    title: "Aegis — Analyseur défensif de sécurité web",
    description:
        "Aegis analyse la posture de sécurité d'un domaine dont tu as prouvé la propriété : HTTPS et TLS, en-têtes HTTP, Content Security Policy, cookies, redirections et cache, avec un rapport priorisé et actionnable.",
    robots: robotsDirective,
    userAgent: "Aegis/1.0 (+https://aegis.paulviandier.com)",
    author: {
        name: "Paul Viandier",
        url: "https://paulviandier.com",
        contactUrl: "https://paulviandier.com/contact"
    },
    repository: "https://github.com/506f6c6c7578/Aegis"
} as const;

export const pages = {
    home: "/",
    verify: "/verifier",
    legalNotice: "/mentions-legales",
    privacy: "/confidentialite"
} as const;

export const reportPathPrefix = "/rapport/";

export function getReportPath(id: string): string {
    return `${reportPathPrefix}${id}`;
}

export const endpoints = {
    challenge: "/api/verification/challenge",
    confirm: "/api/verification/confirm",
    audits: "/api/audits"
} as const;

export function getAuditEndpoint(id: string): string {
    return `${endpoints.audits}/${id}`;
}

export const sections = {
    process: "fonctionnement",
    controls: "controles",
    limits: "limites"
} as const;

export const navigation: readonly NavigationLink[] = [
    { label: "Fonctionnement", href: `/#${sections.process}`, section: sections.process },
    { label: "Contrôles", href: `/#${sections.controls}`, section: sections.controls },
    { label: "Limites", href: `/#${sections.limits}`, section: sections.limits },
    { label: "Vérifier un domaine", href: pages.verify }
];

export const legalLinks = {
    notice: { label: "Mentions légales", href: pages.legalNotice },
    privacy: { label: "Politique de confidentialité", href: pages.privacy }
} as const satisfies Record<string, NavigationLink>;

export const credits: readonly NavigationLink[] = [
    { label: "Recommandations : MDN Web Docs", href: "https://developer.mozilla.org/fr/docs/Web/Security" },
    { label: "Code source sur GitHub", href: site.repository }
];
