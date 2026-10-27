export const verificationPolicy = {
    sessionTtlMs: 2 * 60 * 60_000,
    challengeTtlMs: 30 * 60_000,
    proofTtlMs: 15 * 60_000,
    maxConfirmAttempts: 10,
    confirmCooldownMs: 5_000
} as const;

export const verificationRecordPrefix = "_aegis-verify";

export function getVerificationRecordName(domain: string): string {
    return `${verificationRecordPrefix}.${domain}`;
}
