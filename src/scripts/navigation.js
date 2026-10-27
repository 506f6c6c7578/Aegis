(() => {
    const nav = document.getElementById("site-nav");
    const toggle = document.querySelector("[data-nav-toggle]");
    const linksBySection = new Map(Array.from(nav.querySelectorAll(".nav__link[data-section]"),
        (link) => [link.dataset.section, link]));

    nav.addEventListener("toggle", (event) => toggle.setAttribute("aria-expanded", String(event.newState === "open")));
    nav.addEventListener("click", (event) => {
        if (event.target instanceof Element && event.target.closest("a") && nav.matches(":popover-open")) nav.hidePopover();
    });

    const setActiveLink = (activeLink) => {
        linksBySection.forEach((link) => {
            if (link === activeLink) link.setAttribute("aria-current", "true");
            else link.removeAttribute("aria-current");
        });
    };

    document.addEventListener("DOMContentLoaded", () => {
        const sections = Array.from(document.querySelectorAll("main > section"));
        if (!sections.some((section) => linksBySection.has(section.id))) return;

        const observer = new IntersectionObserver(
            (entries) => {
                entries.filter((entry) => entry.isIntersecting)
                    .forEach((entry) => setActiveLink(linksBySection.get(entry.target.id)));
            },
            { rootMargin: "-45% 0px -50% 0px" }
        );
        sections.forEach((section) => observer.observe(section));
    });
})();
