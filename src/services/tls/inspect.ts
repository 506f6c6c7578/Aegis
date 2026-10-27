import type { DetailedPeerCertificate, PeerCertificate, TLSSocket } from "node:tls";
import type { CertificateDetails, CertificateSummary, TlsFailureReason, TlsObservation } from "@/domain/audit/model";
import { openTlsSocket, type SocketConnector } from "@/lib/network/connector";
import { NetworkError, readErrorCode } from "@/lib/network/errors";
import type { PinnedHost } from "@/lib/network/resolve";
import { type Deadline, waitForSocket } from "@/lib/network/socket";

const maxChainLength = 4;
const maxSubjectAltNames = 20;
const maxNameLength = 160;

const failureReasons: Readonly<Record<string, TlsFailureReason>> = {
    CERT_HAS_EXPIRED: "expired",
    CERT_NOT_YET_VALID: "not-yet-valid",
    ERR_TLS_CERT_ALTNAME_INVALID: "hostname-mismatch",
    DEPTH_ZERO_SELF_SIGNED_CERT: "self-signed",
    SELF_SIGNED_CERT_IN_CHAIN: "self-signed",
    CERT_REVOKED: "revoked",
    UNABLE_TO_VERIFY_LEAF_SIGNATURE: "untrusted-chain",
    UNABLE_TO_GET_ISSUER_CERT: "untrusted-chain",
    UNABLE_TO_GET_ISSUER_CERT_LOCALLY: "untrusted-chain",
    CERT_UNTRUSTED: "untrusted-chain",
    CERT_SIGNATURE_FAILURE: "untrusted-chain",
    CERT_CHAIN_TOO_LONG: "untrusted-chain",
    INVALID_CA: "untrusted-chain",
    ECONNREFUSED: "connection-refused",
    ETIMEDOUT: "timeout",
    EPROTO: "handshake-failed"
};

export function classifyTlsFailure(error: unknown): TlsFailureReason {
    if (error instanceof NetworkError) return error.code === "timeout" ? "timeout" : "connection-failed";
    const code = readErrorCode(error) ?? "";
    return failureReasons[code] ?? (code.startsWith("ERR_SSL_") ? "handshake-failed" : "connection-failed");
}

function readField(value: unknown): string | null {
    const text = Array.isArray(value) ? value.filter((item) => typeof item === "string").join(", ") : value;
    if (typeof text !== "string" || !text.trim()) return null;
    const clean = text.replace(/\p{Cc}/gu, "").trim();
    return clean.length > maxNameLength ? `${clean.slice(0, maxNameLength)}…` : clean;
}

function describeEntity(entity: PeerCertificate["subject"] | undefined): string {
    const commonName = readField(entity?.CN);
    const organization = readField(entity?.O);
    if (organization && commonName && organization !== commonName) return `${organization} (${commonName})`;
    return commonName ?? organization ?? "Non renseigné";
}

function summarize(certificate: PeerCertificate): CertificateSummary {
    return {
        subject: describeEntity(certificate.subject),
        issuer: describeEntity(certificate.issuer),
        validFrom: Date.parse(certificate.valid_from),
        validTo: Date.parse(certificate.valid_to)
    };
}

function describeKey({ asn1Curve, nistCurve, bits }: PeerCertificate): string | null {
    if (asn1Curve) return `ECDSA ${nistCurve ?? asn1Curve}`;
    return bits ? `RSA ${bits} bits` : null;
}

function readSubjectAltNames(certificate: PeerCertificate): string[] {
    return (certificate.subjectaltname ?? "")
        .split(", ")
        .filter((entry) => entry.startsWith("DNS:"))
        .map((entry) => entry.slice(4))
        .slice(0, maxSubjectAltNames);
}

function readChain(leaf: DetailedPeerCertificate): CertificateSummary[] {
    const chain: CertificateSummary[] = [];
    let current = leaf;
    while (chain.length < maxChainLength && current.issuerCertificate && current.issuerCertificate.fingerprint256 !== current.fingerprint256) {
        current = current.issuerCertificate;
        chain.push(summarize(current));
    }
    return chain;
}

function describeConnection(socket: TLSSocket): TlsObservation {
    const certificate = socket.getPeerCertificate(true);
    const cipher = socket.getCipher();
    const details: CertificateDetails = {
        ...summarize(certificate),
        subjectAltNames: readSubjectAltNames(certificate),
        key: describeKey(certificate),
        fingerprint: certificate.fingerprint256
    };
    return {
        status: "established",
        protocol: socket.getProtocol() ?? "Inconnu",
        cipher: cipher.standardName || cipher.name,
        certificate: details,
        chain: readChain(certificate)
    };
}

export async function inspectTls(host: PinnedHost, connector: SocketConnector, deadline: Deadline): Promise<TlsObservation> {
    const socket = openTlsSocket(connector, host);
    try {
        await waitForSocket(socket, "secureConnect", deadline);
        return describeConnection(socket);
    } catch (error) {
        if (error instanceof NetworkError && error.code === "aborted") throw error;
        return { status: "failed", reason: classifyTlsFailure(error) };
    } finally {
        socket.destroy();
    }
}
