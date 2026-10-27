export const brandColors = {
    primary: "#121212",
    body: "#ffffff",
    darkBody: "#1c1c1c",
    accent: "#1f4aa8"
} as const;

export function createLogoMark(foreground: string): string {
    return `<path d="M32 13.5 47 19v12.5c0 9.4-6.3 16.2-15 19.5-8.7-3.3-15-10.1-15-19.5V19Z" fill="none" stroke="${foreground}" stroke-width="3.5" stroke-linejoin="round"/><path d="M32 13.5V51c-8.7-3.3-15-10.1-15-19.5V19Z" fill="${foreground}"/>`;
}

export function createLogoSvg(size: number): string {
    return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 64 64"><rect width="64" height="64" rx="16" fill="${brandColors.primary}"/>${createLogoMark(brandColors.body)}</svg>`;
}
