import { useSyncExternalStore } from "react";

const subscribeToNothing = () => () => {};

export function useHydrated(): boolean {
    return useSyncExternalStore(subscribeToNothing, () => true, () => false);
}
