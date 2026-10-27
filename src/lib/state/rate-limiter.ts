import { createExpiringStore } from "@/lib/state/expiring-store";

export interface RateLimitDecision {
    allowed: boolean;
    retryAfterMs: number;
}

export interface RateLimiter {
    consume: (key: string) => RateLimitDecision;
}

interface RateLimiterOptions {
    limit: number;
    windowMs: number;
    maxKeys: number;
    now?: () => number;
}

interface Window {
    count: number;
    resetAt: number;
}

export function createRateLimiter({ limit, windowMs, maxKeys, now = Date.now }: RateLimiterOptions): RateLimiter {
    const windows = createExpiringStore<Window>({ maxEntries: maxKeys, now });

    return {
        consume: (key) => {
            const time = now();
            const window = windows.get(key) ?? { count: 0, resetAt: time + windowMs };
            if (window.count >= limit) return { allowed: false, retryAfterMs: window.resetAt - time };
            windows.set(key, { count: window.count + 1, resetAt: window.resetAt }, window.resetAt - time);
            return { allowed: true, retryAfterMs: 0 };
        }
    };
}

export function consumeAll(limits: readonly [RateLimiter, string][]): RateLimitDecision {
    const decisions = limits.map(([limiter, key]) => limiter.consume(key));
    const refused = decisions.filter(({ allowed }) => !allowed);
    return refused.length === 0
        ? { allowed: true, retryAfterMs: 0 }
        : { allowed: false, retryAfterMs: Math.max(...refused.map(({ retryAfterMs }) => retryAfterMs)) };
}
