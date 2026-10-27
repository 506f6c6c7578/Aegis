import { type CheckDefinition, createCheck, splitDirectives } from "@/domain/audit/checks";
import type { AuditCheck, HeaderMap, HttpEntry, RedirectChain, ScanObservations, TlsFailureReason, TlsObservation } from "@/domain/audit/model";
import { references } from "@/domain/audit/references";
import { formatDays } from "@/lib/format";

const dayInMs = 86_400_000;
const hstsMinimumAge = 15_552_000;
const hstsRecommendedAge = 31_536_000;
const certificateWarningDays = 30;
const certificateCriticalDays = 14;
const longChainLength = 3;

const definitions = {
    https: { id: "https-available", category: "transport", title: "Disponibilité HTTPS", reference: references.tls },
    chain: { id: "certificate-chain", category: "transport", title: "Chaîne de certificats", reference: references.tls },
    hostname: { id: "certificate-hostname", category: "transport", title: "Correspondance du nom d'hôte", reference: references.tls },
    expiry: { id: "certificate-expiry", category: "transport", title: "Expiration du certificat", reference: references.tls },
    hsts: { id: "hsts", category: "transport", title: "Strict-Transport-Security (HSTS)", reference: references.hsts },
    httpRedirect: { id: "http-redirect", category: "transport", title: "Redirection de HTTP vers HTTPS", reference: references.redirections },
    chainRedirects: { id: "redirect-chain", category: "transport", title: "Chaîne de redirections", reference: references.redirections }
} as const satisfies Record<string, CheckDefinition>;

export const transportCheckIds = { hsts: definitions.hsts.id } as const;

const tlsFailureExplanations: Record<TlsFailureReason, string> = {
    "expired": "Le certificat présenté a expiré : les navigateurs affichent une erreur bloquante.",
    "not-yet-valid": "Le certificat présenté n'est pas encore valide : vérifie sa date de début et l'horloge du serveur.",
    "hostname-mismatch": "Le certificat présenté ne couvre pas ce nom de domaine.",
    "self-signed": "Le certificat est auto-signé et n'est reconnu par aucune autorité de confiance.",
    "untrusted-chain": "La chaîne de certificats est incomplète ou émise par une autorité non reconnue.",
    "revoked": "Le certificat présenté a été révoqué par son autorité.",
    "handshake-failed": "La négociation TLS a échoué : aucune configuration compatible avec TLS 1.2 ou 1.3 n'a été trouvée.",
    "connection-refused": "Le port 443 refuse les connexions : le site n'est pas servi en HTTPS.",
    "timeout": "Le serveur n'a pas répondu en HTTPS dans le délai imparti.",
    "connection-failed": "La connexion HTTPS a été interrompue avant la fin de la négociation."
};

const chainFailures = new Set<TlsFailureReason>(["expired", "not-yet-valid", "self-signed", "untrusted-chain", "revoked"]);

function notEvaluated(definition: CheckDefinition, explanation: string): AuditCheck {
    return createCheck(definition, { status: "not-applicable", priority: "critical", explanation });
}

function analyzeHttps(observations: ScanObservations): AuditCheck {
    const { tls, final } = observations;
    if (tls.status === "failed") {
        return createCheck(definitions.https, {
            status: "fail",
            priority: "critical",
            explanation: tlsFailureExplanations[tls.reason],
            recommendation: "Sers le site en HTTPS avec un certificat valide, par exemple émis automatiquement par Let's Encrypt."
        });
    }
    if (!final) {
        return createCheck(definitions.https, {
            status: "fail",
            priority: "critical",
            explanation: "La connexion TLS aboutit, mais le serveur ne renvoie aucune réponse HTTP exploitable.",
            recommendation: "Vérifie que le serveur web répond bien sur le port 443 pour ce nom d'hôte."
        });
    }
    return createCheck(definitions.https, {
        status: "pass",
        priority: "critical",
        explanation: "Le site répond en HTTPS.",
        observed: `HTTP ${final.status} sur ${final.url}`
    });
}

function analyzeChain(tls: TlsObservation): AuditCheck {
    if (tls.status === "established" || tls.reason === "hostname-mismatch") {
        return createCheck(definitions.chain, {
            status: "pass",
            priority: "critical",
            explanation: "La chaîne de certificats est reconnue par les autorités de confiance.",
            observed: tls.status === "established" ? `Émis par ${tls.certificate.issuer}` : null
        });
    }
    if (!chainFailures.has(tls.reason)) {
        return notEvaluated(definitions.chain, "Le certificat n'a pas pu être examiné car la connexion TLS a échoué.");
    }
    return createCheck(definitions.chain, {
        status: "fail",
        priority: "critical",
        explanation: tlsFailureExplanations[tls.reason],
        recommendation: "Installe un certificat émis par une autorité reconnue et sers la chaîne complète, certificats intermédiaires compris."
    });
}

function analyzeHostname(tls: TlsObservation, domain: string): AuditCheck {
    if (tls.status === "established") {
        return createCheck(definitions.hostname, {
            status: "pass",
            priority: "critical",
            explanation: `Le certificat couvre bien ${domain}.`,
            observed: tls.certificate.subjectAltNames.slice(0, 5).join(", ") || tls.certificate.subject
        });
    }
    if (tls.reason === "hostname-mismatch") {
        return createCheck(definitions.hostname, {
            status: "fail",
            priority: "critical",
            explanation: tlsFailureExplanations[tls.reason],
            recommendation: `Ajoute ${domain} aux noms alternatifs (SAN) du certificat.`
        });
    }
    return notEvaluated(definitions.hostname, "La correspondance ne peut être vérifiée tant que la chaîne de certificats n'est pas valide.");
}

function analyzeExpiry(tls: TlsObservation, now: number): AuditCheck {
    if (tls.status === "failed") {
        return tls.reason === "expired" || tls.reason === "not-yet-valid"
            ? createCheck(definitions.expiry, {
                status: "fail",
                priority: "high",
                explanation: tlsFailureExplanations[tls.reason],
                recommendation: "Renouvelle le certificat et automatise son renouvellement."
            })
            : createCheck(definitions.expiry, {
                status: "not-applicable",
                priority: "high",
                explanation: "Les dates de validité n'ont pas pu être lues."
            });
    }
    const days = Math.floor((tls.certificate.validTo - now) / dayInMs);
    const observed = `Expire dans ${formatDays(days)}`;
    if (days >= certificateWarningDays) {
        return createCheck(definitions.expiry, { status: "pass", priority: "high", explanation: "Le certificat reste valide plus de 30 jours.", observed });
    }
    return createCheck(definitions.expiry, {
        status: days >= certificateCriticalDays ? "warning" : "fail",
        priority: "high",
        explanation: "Le certificat expire bientôt : sans renouvellement, les visiteurs verront une erreur bloquante.",
        recommendation: "Renouvelle le certificat et vérifie que le renouvellement automatique fonctionne.",
        observed
    });
}

function readMaxAge(directives: readonly string[]): number | null {
    const maxAge = directives.find((directive) => directive.startsWith("max-age="));
    const value = maxAge?.slice("max-age=".length).replace(/^"|"$/g, "");
    return value && /^\d{1,12}$/.test(value) ? Number(value) : null;
}

export function analyzeHsts(headers: HeaderMap | null): AuditCheck {
    if (!headers) {
        return createCheck(definitions.hsts, { status: "not-applicable", priority: "high", explanation: "Aucune réponse HTTPS n'a pu être analysée." });
    }
    const value = headers.get("strict-transport-security")?.[0] ?? null;
    if (!value) {
        return createCheck(definitions.hsts, {
            status: "warning",
            priority: "high",
            explanation: "Sans HSTS, une première visite en HTTP reste exposée à une interception avant la redirection.",
            recommendation: "Ajoute Strict-Transport-Security: max-age=63072000; includeSubDomains une fois tous les sous-domaines servis en HTTPS."
        });
    }
    const directives = splitDirectives(value);
    const maxAge = readMaxAge(directives);
    if (maxAge === null || maxAge === 0) {
        return createCheck(definitions.hsts, {
            status: "fail",
            priority: "high",
            explanation: maxAge === 0 ? "max-age=0 désactive HSTS pour ce domaine." : "L'en-tête HSTS ne contient pas de max-age valide : les navigateurs l'ignorent.",
            recommendation: "Définis un max-age d'au moins six mois, idéalement deux ans.",
            observed: value
        });
    }
    if (maxAge < hstsMinimumAge) {
        return createCheck(definitions.hsts, {
            status: "warning",
            priority: "medium",
            explanation: "La durée HSTS est courte : la protection expire rapidement entre deux visites.",
            recommendation: "Augmente max-age à au moins six mois (15552000), idéalement deux ans.",
            observed: value
        });
    }
    const complete = maxAge >= hstsRecommendedAge && directives.includes("includesubdomains");
    return createCheck(definitions.hsts, {
        status: "pass",
        priority: "high",
        explanation: complete
            ? "HSTS est actif pour une longue durée, sous-domaines compris."
            : "HSTS est actif. Une durée d'un an ou plus avec includeSubDomains renforcerait encore la protection.",
        observed: value
    });
}

function analyzeHttpEntry(entry: HttpEntry): AuditCheck {
    if (!entry.available) {
        return createCheck(definitions.httpRedirect, {
            status: "not-applicable",
            priority: "info",
            explanation: "Le port 80 ne répond pas : aucune version HTTP du site n'est exposée."
        });
    }
    const observed = `HTTP ${entry.status}${entry.location ? ` vers ${entry.location}` : ""}`;
    switch (entry.target) {
        case "https-same-host":
            return entry.status === 301 || entry.status === 308
                ? createCheck(definitions.httpRedirect, { status: "pass", priority: "high", explanation: "HTTP redirige de façon permanente vers HTTPS.", observed })
                : createCheck(definitions.httpRedirect, {
                    status: "warning",
                    priority: "medium",
                    explanation: "HTTP redirige vers HTTPS, mais de façon temporaire.",
                    recommendation: "Utilise une redirection permanente (301 ou 308).",
                    observed
                });
        case "https-other-host":
            return createCheck(definitions.httpRedirect, {
                status: "warning",
                priority: "medium",
                explanation: "HTTP redirige vers HTTPS sur un autre nom d'hôte : HSTS ne peut pas être enregistré pour ce domaine dès la première étape.",
                recommendation: "Redirige d'abord vers la version HTTPS du même nom d'hôte, puis vers la destination finale.",
                observed
            });
        case "none":
            return createCheck(definitions.httpRedirect, {
                status: "fail",
                priority: "high",
                explanation: "Le site répond en HTTP sans rediriger vers HTTPS : le trafic peut circuler en clair.",
                recommendation: "Redirige toutes les requêtes HTTP vers HTTPS avec une redirection 301 ou 308.",
                observed
            });
        case "http":
        case "refused":
            return createCheck(definitions.httpRedirect, {
                status: "fail",
                priority: "high",
                explanation: "La redirection depuis HTTP ne mène pas vers une destination HTTPS valide.",
                recommendation: "Redirige toutes les requêtes HTTP vers https:// sur le même nom d'hôte.",
                observed
            });
    }
}

const refusedRedirectExplanations = {
    "invalid-location": "Une redirection pointe vers une adresse invalide.",
    "unsupported-scheme": "Une redirection pointe vers un protocole autre que HTTP ou HTTPS.",
    "credentials": "Une redirection contient des identifiants dans l'URL.",
    "port": "Une redirection pointe vers un port non standard.",
    "ip-literal": "Une redirection pointe vers une adresse IP brute plutôt qu'un nom de domaine.",
    "invalid-host": "Une redirection pointe vers un nom d'hôte invalide ou non public."
} as const;

function analyzeRedirectChain({ hops, outcome, refusedDestination }: RedirectChain): AuditCheck {
    const redirects = Math.max(hops.length - 1, 0);
    const observed = hops.map(({ status, url }) => `${status} ${url}`).join(" → ") || null;
    switch (outcome) {
        case "completed":
            return redirects < longChainLength
                ? createCheck(definitions.chainRedirects, {
                    status: "pass",
                    priority: "medium",
                    explanation: redirects === 0 ? "La page d'accueil répond directement, sans redirection." : "La chaîne de redirections est courte et reste en HTTPS.",
                    observed
                })
                : createCheck(definitions.chainRedirects, {
                    status: "warning",
                    priority: "low",
                    explanation: "La chaîne de redirections est longue : chaque étape ralentit le chargement.",
                    recommendation: "Redirige directement vers l'adresse finale.",
                    observed
                });
        case "out-of-scope":
            return createCheck(definitions.chainRedirects, {
                status: "warning",
                priority: "info",
                explanation: "La redirection quitte le domaine vérifié : Aegis ne la suit pas et analyse la dernière réponse obtenue.",
                observed: refusedDestination ? `${observed ?? ""} → ${refusedDestination}` : observed
            });
        case "insecure-redirect":
            return createCheck(definitions.chainRedirects, {
                status: "fail",
                priority: "high",
                explanation: "Une redirection ramène de HTTPS vers HTTP : la connexion repasse en clair.",
                recommendation: "Garde toutes les redirections en HTTPS.",
                observed
            });
        case "loop":
            return createCheck(definitions.chainRedirects, {
                status: "fail",
                priority: "high",
                explanation: "Les redirections forment une boucle : la page ne peut pas s'afficher.",
                recommendation: "Corrige les règles de redirection pour aboutir à une page finale.",
                observed
            });
        case "too-many-redirects":
            return createCheck(definitions.chainRedirects, {
                status: "fail",
                priority: "medium",
                explanation: "Plus de cinq redirections se succèdent : Aegis s'arrête à cette limite.",
                recommendation: "Réduis la chaîne à une ou deux redirections.",
                observed
            });
        case "missing-location":
            return createCheck(definitions.chainRedirects, {
                status: "fail",
                priority: "low",
                explanation: "Une réponse de redirection ne précise aucune destination (en-tête Location absent).",
                recommendation: "Ajoute l'en-tête Location aux réponses de redirection.",
                observed
            });
        case "request-failed":
            return createCheck(definitions.chainRedirects, {
                status: "warning",
                priority: "medium",
                explanation: "Une étape de la chaîne de redirections n'a pas répondu.",
                recommendation: "Vérifie que chaque destination de redirection est accessible en HTTPS.",
                observed
            });
        default:
            return createCheck(definitions.chainRedirects, {
                status: "fail",
                priority: "medium",
                explanation: `${refusedRedirectExplanations[outcome]} Aegis ne la suit pas.`,
                recommendation: "Redirige uniquement vers des URL HTTPS sur un nom de domaine public, sans port ni identifiants.",
                observed
            });
    }
}

export function analyzeTransport(observations: ScanObservations, now: number): AuditCheck[] {
    return [
        analyzeHttps(observations),
        analyzeChain(observations.tls),
        analyzeHostname(observations.tls, observations.domain),
        analyzeExpiry(observations.tls, now),
        analyzeHsts(observations.final?.headers ?? null),
        analyzeHttpEntry(observations.httpEntry),
        analyzeRedirectChain(observations.chain)
    ];
}
