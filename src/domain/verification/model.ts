export interface IssuedChallenge {
    domain: string;
    displayDomain: string;
    recordName: string;
    recordValue: string;
    expiresAt: number;
}

export const pendingReasons = ["not-found", "mismatch", "dns-error"] as const;
export type PendingReason = (typeof pendingReasons)[number];

export type Confirmation =
    | { status: "pending"; reason: PendingReason; attemptsRemaining: number; retryAfterMs: number }
    | { status: "verified"; domain: string; expiresAt: number };
