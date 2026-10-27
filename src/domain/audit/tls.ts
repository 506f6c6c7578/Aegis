import { type CheckDefinition, createCheck } from "@/domain/audit/checks";
import type { AuditCheck, TlsObservation } from "@/domain/audit/model";
import { references } from "@/domain/audit/references";

const definitions = {
    protocol: { id: "tls-protocol", category: "tls", title: "Protocole TLS négocié", reference: references.tlsConfiguration },
    cipher: { id: "tls-cipher", category: "tls", title: "Suite cryptographique négociée", reference: references.tlsConfiguration }
} as const satisfies Record<string, CheckDefinition>;

const authenticatedEncryption = /_GCM_|CHACHA20|_CCM/;
const forwardSecrecy = /^TLS_(?:ECDHE|DHE)_/;

function analyzeProtocol(tls: TlsObservation): AuditCheck {
    if (tls.status === "failed") {
        return tls.reason === "handshake-failed"
            ? createCheck(definitions.protocol, {
                status: "fail",
                priority: "high",
                explanation: "Aucune version moderne de TLS n'a pu être négociée. Aegis ne teste volontairement pas les versions obsolètes.",
                recommendation: "Active TLS 1.2 et TLS 1.3 et désactive les versions antérieures."
            })
            : createCheck(definitions.protocol, { status: "not-applicable", priority: "high", explanation: "La connexion TLS n'a pas abouti." });
    }
    if (tls.protocol === "TLSv1.3") {
        return createCheck(definitions.protocol, { status: "pass", priority: "high", explanation: "TLS 1.3, la version la plus récente, a été négociée.", observed: tls.protocol });
    }
    if (tls.protocol === "TLSv1.2") {
        return createCheck(definitions.protocol, {
            status: "warning",
            priority: "low",
            explanation: "TLS 1.2 reste sûr, mais TLS 1.3 n'a pas été proposé par le serveur.",
            recommendation: "Active TLS 1.3, plus rapide et plus simple à configurer de façon sûre.",
            observed: tls.protocol
        });
    }
    return createCheck(definitions.protocol, {
        status: "fail",
        priority: "high",
        explanation: "Une version de TLS inattendue a été négociée.",
        recommendation: "Limite le serveur à TLS 1.2 et TLS 1.3.",
        observed: tls.protocol
    });
}

function analyzeCipher(tls: TlsObservation): AuditCheck {
    if (tls.status === "failed") {
        return createCheck(definitions.cipher, { status: "not-applicable", priority: "medium", explanation: "Aucune suite n'a été négociée." });
    }
    const observed = tls.cipher;
    if (tls.protocol === "TLSv1.3" || (authenticatedEncryption.test(tls.cipher) && forwardSecrecy.test(tls.cipher))) {
        return createCheck(definitions.cipher, {
            status: "pass",
            priority: "medium",
            explanation: "La suite négociée assure la confidentialité persistante et un chiffrement authentifié.",
            observed
        });
    }
    if (forwardSecrecy.test(tls.cipher)) {
        return createCheck(definitions.cipher, {
            status: "warning",
            priority: "medium",
            explanation: "La suite négociée repose sur un mode de chiffrement CBC, moins robuste que les modes authentifiés.",
            recommendation: "Privilégie les suites AES-GCM ou ChaCha20-Poly1305.",
            observed
        });
    }
    return createCheck(definitions.cipher, {
        status: "fail",
        priority: "medium",
        explanation: "La suite négociée n'assure pas la confidentialité persistante : une fuite de la clé privée exposerait le trafic passé.",
        recommendation: "Privilégie les suites ECDHE avec AES-GCM ou ChaCha20-Poly1305.",
        observed
    });
}

export function analyzeTls(tls: TlsObservation): AuditCheck[] {
    return [analyzeProtocol(tls), analyzeCipher(tls)];
}
