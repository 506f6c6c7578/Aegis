import type { AstroCookies } from "astro";

export const cookieNames = {
    session: "__Host-aegis-session",
    challenge: "__Host-aegis-challenge",
    proof: "__Host-aegis-proof"
} as const;

type CookieName = (typeof cookieNames)[keyof typeof cookieNames];

const baseOptions = { httpOnly: true, secure: true, sameSite: "strict", path: "/" } as const;

export function readCookie(cookies: AstroCookies, name: CookieName): string | undefined {
    return cookies.get(name)?.value;
}

export function writeCookie(cookies: AstroCookies, name: CookieName, value: string, expiresAt: number, now = Date.now()): void {
    cookies.set(name, value, { ...baseOptions, maxAge: Math.max(1, Math.floor((expiresAt - now) / 1_000)) });
}

export function clearCookie(cookies: AstroCookies, name: CookieName): void {
    cookies.delete(name, baseOptions);
}
