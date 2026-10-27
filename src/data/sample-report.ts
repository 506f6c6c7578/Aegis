import type { HeaderMap, ScanObservations } from "@/domain/audit/model";
import { buildReport } from "@/domain/audit/report";

const dayInMs = 86_400_000;
const startedAt = Date.UTC(2026, 9, 1, 8, 30);
const domain = "mon-site.example";

const headers: HeaderMap = new Map([
    ["strict-transport-security", ["max-age=31536000"]],
    ["content-security-policy", ["default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; img-src 'self' https:"]],
    ["x-content-type-options", ["nosniff"]],
    ["referrer-policy", ["strict-origin-when-cross-origin"]],
    ["x-frame-options", ["SAMEORIGIN"]],
    ["cache-control", ["no-cache"]],
    ["server", ["nginx/1.27.0"]],
    ["set-cookie", ["session_id=valeur-fictive; Path=/; Secure; SameSite=Lax", "preferences=valeur-fictive; Path=/; Max-Age=2592000; Secure; SameSite=Lax"]]
]);

const observations: ScanObservations = {
    domain,
    tls: {
        status: "established",
        protocol: "TLSv1.3",
        cipher: "TLS_AES_128_GCM_SHA256",
        certificate: {
            subject: domain,
            issuer: "Autorité fictive (Démo R1)",
            validFrom: startedAt - 40 * dayInMs,
            validTo: startedAt + 50 * dayInMs,
            subjectAltNames: [domain, `www.${domain}`],
            key: "ECDSA P-256",
            fingerprint: "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"
        },
        chain: [{ subject: "Démo R1", issuer: "Racine fictive", validFrom: startedAt - 400 * dayInMs, validTo: startedAt + 700 * dayInMs }]
    },
    chain: {
        hops: [
            { url: `https://${domain}/`, status: 301, method: "HEAD", location: `https://www.${domain}/` },
            { url: `https://www.${domain}/`, status: 200, method: "HEAD", location: null }
        ],
        outcome: "completed",
        refusedDestination: null
    },
    final: { url: `https://www.${domain}/`, status: 200, method: "HEAD", headers },
    httpEntry: { available: true, status: 301, target: "https-same-host", location: `https://${domain}/` },
    metaPolicies: []
};

export const sampleReport = buildReport({
    id: "rapport-fictif",
    displayDomain: domain,
    observations,
    startedAt,
    completedAt: startedAt + 1_840,
    expiresAt: startedAt + 30 * 60_000
});
