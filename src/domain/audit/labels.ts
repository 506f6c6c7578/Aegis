import type { CategoryId, CheckStatus, Priority } from "@/domain/audit/model";

export const statusLabels: Record<CheckStatus, string> = {
    "pass": "Conforme",
    "warning": "Recommandation",
    "fail": "Problème",
    "not-applicable": "Non applicable"
};

export const priorityLabels: Record<Priority, string> = {
    critical: "Critique",
    high: "Élevée",
    medium: "Moyenne",
    low: "Faible",
    info: "Information"
};

export const categories: Record<CategoryId, { label: string; weight: number; description: string }> = {
    transport: {
        label: "HTTPS, certificat et redirections",
        weight: 25,
        description: "Disponibilité HTTPS, validité du certificat, HSTS et passage de HTTP vers HTTPS."
    },
    tls: {
        label: "TLS négocié",
        weight: 10,
        description: "Version du protocole et suite cryptographique retenues lors de la connexion."
    },
    headers: {
        label: "En-têtes HTTP de sécurité",
        weight: 25,
        description: "Protections du navigateur : type MIME, référent, permissions, isolation et intégration en cadre."
    },
    csp: {
        label: "Content Security Policy",
        weight: 20,
        description: "Sources autorisées pour les scripts, objets, formulaires et l'URL de base."
    },
    cookies: {
        label: "Cookies",
        weight: 15,
        description: "Attributs Secure, HttpOnly, SameSite, portée et durée des cookies déposés."
    },
    cache: {
        label: "Cache et informations exposées",
        weight: 5,
        description: "Règles de mise en cache et informations divulguées sur le serveur."
    }
};
