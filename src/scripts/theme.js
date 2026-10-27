(() => {
    const storageKey = "theme";
    const root = document.documentElement;
    const darkScheme = window.matchMedia("(prefers-color-scheme: dark)");
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

    const getStoredTheme = () => {
        try {
            const theme = localStorage.getItem(storageKey);
            return theme === "dark" || theme === "light" ? theme : null;
        } catch {
            return null;
        }
    };

    const getTheme = () => getStoredTheme() ?? (darkScheme.matches ? "dark" : "light");

    const applyTheme = (theme) => {
        root.classList.toggle("dark", theme === "dark");
        document.querySelectorAll("[data-theme-switcher]").forEach((switcher) => {
            switcher.setAttribute("aria-checked", String(theme === "dark"));
        });
    };

    const switchTheme = (theme) => {
        if (!document.startViewTransition || reducedMotion.matches) {
            applyTheme(theme);
            return;
        }
        root.classList.add("theme-switching");
        document
            .startViewTransition(() => applyTheme(theme))
            .finished.finally(() => root.classList.remove("theme-switching"));
    };

    applyTheme(getTheme());
    darkScheme.addEventListener("change", () => switchTheme(getTheme()));
    document.addEventListener("DOMContentLoaded", () => applyTheme(getTheme()));
    document.addEventListener("click", (event) => {
        if (!(event.target instanceof Element) ||
            !event.target.closest("[data-theme-switcher]")) return;
        const theme = root.classList.contains("dark") ? "light" : "dark";
        try {
            localStorage.setItem(storageKey, theme);
        } catch {
        }
        switchTheme(theme);
    });
})();
