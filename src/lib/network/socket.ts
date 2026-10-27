import type { Socket } from "node:net";
import { NetworkError } from "@/lib/network/errors";

export interface Deadline {
    timeoutMs: number;
    signal: AbortSignal;
}

export function waitForSocket(socket: Socket, event: "connect" | "secureConnect", { timeoutMs, signal }: Deadline): Promise<void> {
    return new Promise((resolve, reject) => {
        const settle = (error?: unknown) => {
            clearTimeout(timer);
            socket.off(event, onReady);
            socket.off("error", settle);
            signal.removeEventListener("abort", onAbort);
            if (error === undefined) {
                resolve();
                return;
            }
            socket.destroy();
            reject(error);
        };
        const onReady = () => settle();
        const onAbort = () => settle(new NetworkError("aborted"));
        const timer = setTimeout(() => settle(new NetworkError("timeout")), timeoutMs);
        if (signal.aborted) {
            onAbort();
            return;
        }
        socket.once(event, onReady);
        socket.once("error", settle);
        signal.addEventListener("abort", onAbort, { once: true });
    });
}
