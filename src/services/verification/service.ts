import type { NormalizedHostname } from "@/domain/domain/hostname";
import { hashChallengeToken, matchesChallenge } from "@/domain/verification/challenge";
import type { IssuedChallenge, PendingReason } from "@/domain/verification/model";
import { getVerificationRecordName, verificationPolicy } from "@/domain/verification/policy";
import { challengeTokenSchema, type ProofToken, proofTokenSchema, type SessionToken, sessionTokenSchema } from "@/domain/verification/tokens";
import { createRandomToken } from "@/lib/crypto/random";
import type { TokenSigner } from "@/lib/crypto/signed-token";
import { NetworkError } from "@/lib/network/errors";
import { createExpiringStore } from "@/lib/state/expiring-store";
import { consumeAll, createRateLimiter } from "@/lib/state/rate-limiter";
import type { ControlledResolver } from "@/services/dns/resolver";

const stateCapacity = 10_000;
const limitWindowMs = 15 * 60_000;

export interface Session {
    payload: SessionToken;
    token: string;
}

export type ChallengeResult =
    | { ok: true; challenge: IssuedChallenge; challengeToken: string }
    | { ok: false; error: "rate-limited"; retryAfterMs: number };

export type ConfirmResult =
    | { ok: true; status: "verified"; domain: string; expiresAt: number; proofToken: string }
    | { ok: true; status: "pending"; reason: PendingReason; attemptsRemaining: number; retryAfterMs: number }
    | { ok: false; error: "challenge-missing" }
    | { ok: false; error: "attempts-exhausted" }
    | { ok: false; error: "rate-limited"; retryAfterMs: number };

export interface VerificationService {
    readSession: (token: string | undefined) => SessionToken | null;
    openSession: (token: string | undefined) => Session;
    issueChallenge: (input: { session: SessionToken; hostname: NormalizedHostname; client: string }) => ChallengeResult;
    confirmChallenge: (input: { session: SessionToken; challengeToken: string | undefined; client: string }) => Promise<ConfirmResult>;
    readProof: (input: { session: SessionToken; proofToken: string | undefined; domain: string }) => ProofToken | null;
}

interface VerificationDependencies {
    signer: TokenSigner;
    resolver: Pick<ControlledResolver, "resolveTxt">;
    now?: () => number;
}

interface AttemptState {
    count: number;
    lastAt: number;
}

export function createVerificationService({ signer, resolver, now = Date.now }: VerificationDependencies): VerificationService {
    const consumedChallenges = createExpiringStore<true>({ maxEntries: stateCapacity, now });
    const attempts = createExpiringStore<AttemptState>({ maxEntries: stateCapacity, now });
    const limiterOptions = { windowMs: limitWindowMs, maxKeys: stateCapacity, now };
    const challengesByClient = createRateLimiter({ ...limiterOptions, limit: 10 });
    const challengesBySession = createRateLimiter({ ...limiterOptions, limit: 10 });
    const confirmationsByClient = createRateLimiter({ ...limiterOptions, limit: 60 });

    const readSession: VerificationService["readSession"] = (token) => signer.verify("session", token, sessionTokenSchema, now());

    const openSession: VerificationService["openSession"] = (token) => {
        const sid = readSession(token)?.sid ?? createRandomToken();
        const payload = { sid, exp: now() + verificationPolicy.sessionTtlMs };
        return { payload, token: signer.sign("session", payload) };
    };

    const issueChallenge: VerificationService["issueChallenge"] = ({ session, hostname, client }) => {
        const limit = consumeAll([[challengesByClient, client], [challengesBySession, session.sid]]);
        if (!limit.allowed) return { ok: false, error: "rate-limited", retryAfterMs: limit.retryAfterMs };

        const challengeId = createRandomToken();
        const token = createRandomToken();
        const expiresAt = now() + verificationPolicy.challengeTtlMs;
        const hash = hashChallengeToken({ challengeId, domain: hostname.ascii }, token);
        return {
            ok: true,
            challengeToken: signer.sign("challenge", { cid: challengeId, sid: session.sid, domain: hostname.ascii, hash, exp: expiresAt }),
            challenge: {
                domain: hostname.ascii,
                displayDomain: hostname.unicode,
                recordName: getVerificationRecordName(hostname.ascii),
                recordValue: token,
                expiresAt
            }
        };
    };

    const confirmChallenge: VerificationService["confirmChallenge"] = async ({ session, challengeToken, client }) => {
        const time = now();
        const challenge = signer.verify("challenge", challengeToken, challengeTokenSchema, time);
        if (!challenge || challenge.sid !== session.sid || consumedChallenges.get(challenge.cid)) return { ok: false, error: "challenge-missing" };

        const limit = confirmationsByClient.consume(client);
        if (!limit.allowed) return { ok: false, error: "rate-limited", retryAfterMs: limit.retryAfterMs };

        const previous = attempts.get(challenge.cid) ?? { count: 0, lastAt: 0 };
        if (previous.count >= verificationPolicy.maxConfirmAttempts) return { ok: false, error: "attempts-exhausted" };
        const cooldown = previous.lastAt + verificationPolicy.confirmCooldownMs - time;
        if (cooldown > 0) return { ok: false, error: "rate-limited", retryAfterMs: cooldown };
        const attempt = { count: previous.count + 1, lastAt: time };
        attempts.set(challenge.cid, attempt, challenge.exp - time);

        const pending = (reason: PendingReason): ConfirmResult => ({
            ok: true,
            status: "pending",
            reason,
            attemptsRemaining: verificationPolicy.maxConfirmAttempts - attempt.count,
            retryAfterMs: verificationPolicy.confirmCooldownMs
        });

        let records: readonly (readonly string[])[];
        try {
            records = await resolver.resolveTxt(getVerificationRecordName(challenge.domain));
        } catch (error) {
            if (error instanceof NetworkError) return pending("dns-error");
            throw error;
        }
        if (!matchesChallenge(records, { challengeId: challenge.cid, domain: challenge.domain }, challenge.hash)) {
            return pending(records.length === 0 ? "not-found" : "mismatch");
        }
        if (consumedChallenges.get(challenge.cid)) return { ok: false, error: "challenge-missing" };

        consumedChallenges.set(challenge.cid, true, challenge.exp - time);
        attempts.delete(challenge.cid);
        const expiresAt = now() + verificationPolicy.proofTtlMs;
        return {
            ok: true,
            status: "verified",
            domain: challenge.domain,
            expiresAt,
            proofToken: signer.sign("proof", { cid: challenge.cid, sid: session.sid, domain: challenge.domain, exp: expiresAt })
        };
    };

    const readProof: VerificationService["readProof"] = ({ session, proofToken, domain }) => {
        const proof = signer.verify("proof", proofToken, proofTokenSchema, now());
        return proof && proof.sid === session.sid && proof.domain === domain ? proof : null;
    };

    return { readSession, openSession, issueChallenge, confirmChallenge, readProof };
}
