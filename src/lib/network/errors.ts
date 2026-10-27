export type NetworkErrorCode =
    | "dns-not-found"
    | "dns-failure"
    | "forbidden-address"
    | "timeout"
    | "aborted"
    | "connection-refused"
    | "connection-failed"
    | "tls-failure"
    | "invalid-response";

export class NetworkError extends Error {
    override readonly name = "NetworkError";

    constructor(readonly code: NetworkErrorCode) {
        super(code);
    }
}

const socketErrorCodes: Readonly<Record<string, NetworkErrorCode>> = {
    ECONNREFUSED: "connection-refused",
    ETIMEDOUT: "timeout",
    ECONNRESET: "connection-failed",
    EHOSTUNREACH: "connection-failed",
    ENETUNREACH: "connection-failed",
    EPIPE: "connection-failed",
    HPE_HEADER_OVERFLOW: "invalid-response",
    HPE_INVALID_CONSTANT: "invalid-response",
    HPE_INVALID_HEADER_TOKEN: "invalid-response",
    HPE_INVALID_STATUS: "invalid-response",
    HPE_INVALID_VERSION: "invalid-response",
    HPE_UNEXPECTED_CONTENT_LENGTH: "invalid-response",
    ABORT_ERR: "aborted"
};

const tlsErrorPattern = /^(?:ERR_TLS_|ERR_SSL_|CERT_|UNABLE_TO_|DEPTH_ZERO_|SELF_SIGNED_|EPROTO$)/;

export function readErrorCode(error: unknown): string | undefined {
    if (typeof error !== "object" || error === null || !("code" in error)) return undefined;
    return typeof error.code === "string" ? error.code : undefined;
}

export function toNetworkError(error: unknown): NetworkError {
    if (error instanceof NetworkError) return error;
    const code = readErrorCode(error) ?? "";
    if (tlsErrorPattern.test(code)) return new NetworkError("tls-failure");
    return new NetworkError(socketErrorCodes[code] ?? "connection-failed");
}
