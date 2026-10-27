const maxDisplayPathLength = 120;

export function formatDisplayUrl(url: URL): string {
    const path = url.pathname.length > maxDisplayPathLength ? `${url.pathname.slice(0, maxDisplayPathLength)}…` : url.pathname;
    return `${url.protocol}//${url.host}${path}${url.search ? "?…" : ""}`;
}
