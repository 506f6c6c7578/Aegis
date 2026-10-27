import { useCallback, useEffect, useState } from "react";
import * as z from "zod/mini";
import type { IssuedChallenge, PendingReason } from "@/domain/verification/model";
import { ApiError, api, challengeSchema } from "@/lib/client/api";

const storageKey = "aegis:verification";

export type CheckState =
    | { kind: "idle" }
    | { kind: "checking" }
    | { kind: "pending"; reason: PendingReason; attemptsRemaining: number; retryAt: number }
    | { kind: "error"; message: string; retryAt: number | null };

export type VerificationState =
    | { step: "loading" }
    | { step: "domain" }
    | { step: "challenge"; challenge: IssuedChallenge; check: CheckState }
    | { step: "verified"; challenge: IssuedChallenge; expiresAt: number };

const storedStateSchema = z.object({ challenge: challengeSchema, verifiedUntil: z.nullable(z.number()) });

function readStoredState(now: number): VerificationState {
    try {
        const result = storedStateSchema.safeParse(JSON.parse(sessionStorage.getItem(storageKey) ?? "null"));
        if (!result.success) return { step: "domain" };
        const { challenge, verifiedUntil } = result.data;
        if (verifiedUntil !== null && verifiedUntil > now) return { step: "verified", challenge, expiresAt: verifiedUntil };
        return challenge.expiresAt > now && verifiedUntil === null ? { step: "challenge", challenge, check: { kind: "idle" } } : { step: "domain" };
    } catch {
        return { step: "domain" };
    }
}

function writeStoredState(state: VerificationState): void {
    if (state.step === "loading") return;
    try {
        if (state.step === "domain") sessionStorage.removeItem(storageKey);
        else sessionStorage.setItem(storageKey, JSON.stringify({ challenge: state.challenge, verifiedUntil: state.step === "verified" ? state.expiresAt : null }));
    } catch {
    }
}

function toMessage(error: unknown): string {
    return error instanceof ApiError ? error.message : "Une erreur inattendue est survenue.";
}

export function useVerification() {
    const [state, setState] = useState<VerificationState>({ step: "loading" });
    const [submitting, setSubmitting] = useState(false);
    const [formError, setFormError] = useState<string | null>(null);
    useEffect(() => setState(readStoredState(Date.now())), []);
    useEffect(() => writeStoredState(state), [state]);

    const submitDomain = useCallback(async (domain: string) => {
        setSubmitting(true);
        setFormError(null);
        try {
            const challenge = await api.createChallenge(domain);
            setState({ step: "challenge", challenge, check: { kind: "idle" } });
        } catch (error) {
            setFormError(toMessage(error));
        } finally {
            setSubmitting(false);
        }
    }, []);

    const confirm = useCallback(async () => {
        if (state.step !== "challenge") return;
        const { challenge } = state;
        setState({ step: "challenge", challenge, check: { kind: "checking" } });
        try {
            const result = await api.confirmChallenge();
            setState(result.status === "verified"
                ? { step: "verified", challenge, expiresAt: result.expiresAt }
                : {
                    step: "challenge",
                    challenge,
                    check: { kind: "pending", reason: result.reason, attemptsRemaining: result.attemptsRemaining, retryAt: Date.now() + result.retryAfterMs }
                });
        } catch (error) {
            if (error instanceof ApiError && (error.code === "challenge-missing" || error.code === "attempts-exhausted")) {
                setFormError(error.message);
                setState({ step: "domain" });
                return;
            }
            const retryAt = error instanceof ApiError && error.retryAfterMs ? Date.now() + error.retryAfterMs : null;
            setState({ step: "challenge", challenge, check: { kind: "error", message: toMessage(error), retryAt } });
        }
    }, [state]);

    const reset = useCallback(() => {
        setFormError(null);
        setState({ step: "domain" });
    }, []);

    return { state, submitting, formError, submitDomain, confirm, reset };
}
