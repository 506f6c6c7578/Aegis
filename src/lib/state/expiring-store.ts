interface Entry<Value> {
    value: Value;
    expiresAt: number;
}

export interface ExpiringStore<Value> {
    get: (key: string) => Value | undefined;
    set: (key: string, value: Value, ttlMs: number) => void;
    delete: (key: string) => void;
    size: () => number;
}

interface ExpiringStoreOptions {
    maxEntries: number;
    now?: () => number;
}

export function createExpiringStore<Value>({ maxEntries, now = Date.now }: ExpiringStoreOptions): ExpiringStore<Value> {
    const entries = new Map<string, Entry<Value>>();

    const evict = (time: number) => {
        for (const [key, entry] of entries) {
            if (entry.expiresAt > time) break;
            entries.delete(key);
        }
        while (entries.size >= maxEntries) {
            const oldest = entries.keys().next();
            if (oldest.done) break;
            entries.delete(oldest.value);
        }
    };

    return {
        get: (key) => {
            const entry = entries.get(key);
            if (!entry) return undefined;
            if (entry.expiresAt > now()) return entry.value;
            entries.delete(key);
            return undefined;
        },
        set: (key, value, ttlMs) => {
            const time = now();
            entries.delete(key);
            evict(time);
            entries.set(key, { value, expiresAt: time + ttlMs });
        },
        delete: (key) => {
            entries.delete(key);
        },
        size: () => entries.size
    };
}
