import { expect, type Page, test } from "@playwright/test";
import { sampleReport } from "@/data/sample-report";

const reportId = "R".repeat(43);
const challenge = {
    domain: "xn--bcher-kva.aegis-test.fr",
    displayDomain: "bücher.aegis-test.fr",
    recordName: "_aegis-verify.xn--bcher-kva.aegis-test.fr",
    recordValue: "jeton-de-demonstration-0123456789abcdefghijk",
    expiresAt: Date.now() + 30 * 60_000
};

async function mockVerification(page: Page, confirmations: readonly object[]) {
    const requests: string[] = [];
    let index = 0;
    await page.route("**/api/verification/challenge", async (route) => {
        requests.push(route.request().postData() ?? "");
        await route.fulfill({ status: 201, json: { challenge } });
    });
    await page.route("**/api/verification/confirm", async (route) => {
        const response = confirmations[Math.min(index, confirmations.length - 1)];
        index += 1;
        await route.fulfill({ status: 200, json: response });
    });
    await page.route("**/api/audits", (route) => route.fulfill({ status: 201, json: { id: reportId, expiresAt: Date.now() + 30 * 60_000 } }));
    return requests;
}

async function openVerification(page: Page) {
    await page.goto("/verifier");
    await expect(page.getByRole("button", { name: "Générer le challenge" })).toBeEnabled();
}

async function mockReport(page: Page, response: { status: number; json: object }, delayMs = 0) {
    await page.route(`**/api/audits/${reportId}`, async (route) => {
        if (delayMs) await new Promise((resolve) => setTimeout(resolve, delayMs));
        await route.fulfill(response);
    });
}

const verified = { status: "verified", domain: challenge.domain, expiresAt: Date.now() + 15 * 60_000 };
const pending = { status: "pending", reason: "not-found", attemptsRemaining: 9, retryAfterMs: 1_000 };

test.describe("accueil", () => {
    test("présente l'outil, ses limites et un rapport fictif", async ({ page }) => {
        await page.goto("/");
        await expect(page).toHaveTitle("Aegis — Analyseur défensif de sécurité web");
        await expect(page.getByRole("heading", { level: 1 })).toHaveText("Comprends la posture de sécurité de ton domaine.");
        await expect(page.getByText("Rapport fictif pour le domaine réservé mon-site.example")).toBeVisible();
        await expect(page.getByRole("heading", { name: "Un outil défensif, volontairement borné" })).toBeAttached();
        await expect(page.getByRole("link", { name: "Voir le portfolio" })).toHaveAttribute("href", "https://paulviandier.com");
        await page.getByRole("main").getByRole("link", { name: "Vérifier un domaine" }).click();
        await expect(page).toHaveURL(/\/verifier$/);
    });
});

test.describe("vérification d'un domaine", () => {
    test("garde le panneau d'aide à droite du formulaire après hydratation", async ({ page, isMobile }) => {
        test.skip(isMobile, "Deux colonnes uniquement sur grand écran");
        await page.setViewportSize({ width: 1543, height: 760 });
        await openVerification(page);
        const form = await page.getByRole("heading", { name: "Quel domaine veux-tu analyser ?" }).boundingBox();
        const aside = await page.getByRole("complementary", { name: "À savoir" }).boundingBox();
        expect(aside && form && aside.x > form.x + form.width && Math.abs(aside.y - form.y) < 120).toBe(true);
    });

    test("refuse une URL complète sans contacter le serveur", async ({ page }) => {
        const requests = await mockVerification(page, [pending]);
        await openVerification(page);
        await page.getByLabel("Nom de domaine").fill("https://aegis-test.fr/admin");
        await page.getByRole("button", { name: "Générer le challenge" }).click();
        await expect(page.getByText("Saisis uniquement le nom de domaine, sans protocole")).toBeVisible();
        await expect(page.getByLabel("Nom de domaine")).toHaveAttribute("aria-invalid", "true");
        expect(requests).toHaveLength(0);
    });

    test("affiche le domaine normalisé, le challenge copiable et l'attente de propagation", async ({ page, context, browserName }) => {
        test.skip(browserName !== "chromium", "Permissions du presse-papiers propres à Chromium");
        await context.grantPermissions(["clipboard-read", "clipboard-write"]);
        await mockVerification(page, [pending, verified]);
        await openVerification(page);
        await page.getByLabel("Nom de domaine").fill("Bücher.aegis-test.fr");
        await page.getByRole("button", { name: "Générer le challenge" }).click();

        await expect(page.getByTestId("normalized-domain")).toHaveText(challenge.domain);
        await expect(page.getByText(`Affiché : ${challenge.displayDomain}`)).toBeVisible();
        await expect(page.getByText(challenge.recordName)).toBeVisible();
        await page.getByRole("button", { name: "Copier : Valeur" }).click();
        const confirmation = page.locator('[data-slot="toast"]').getByText("Valeur copiée", { exact: true });
        await expect(confirmation).toBeVisible();
        expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(challenge.recordValue);
        await expect(confirmation).toBeHidden({ timeout: 6_500 });

        await page.getByRole("button", { name: "Vérifier l'enregistrement" }).click();
        await expect(page.getByText("Enregistrement introuvable pour l'instant")).toBeVisible();
        await expect(page.getByText("9 tentatives restantes")).toBeVisible();

        await page.route("**/_astro/*.js", async (route) => {
            await new Promise((resolve) => setTimeout(resolve, 800));
            await route.continue();
        });
        await page.reload({ waitUntil: "commit" });
        await expect(page.getByRole("status", { name: "Chargement de la vérification" })).toBeVisible();
        await expect(page.getByRole("heading", { name: "Quel domaine veux-tu analyser ?" })).toHaveCount(0);
        await expect(page.getByTestId("normalized-domain")).toHaveText(challenge.domain);
        await expect(page.getByRole("status", { name: "Chargement de la vérification" })).toHaveCount(0);
        await page.unroute("**/_astro/*.js");
        await page.getByRole("button", { name: "Vérifier l'enregistrement" }).click();
        await expect(page.getByText("Propriété vérifiée")).toBeVisible();
    });

    test("confirme puis lance l'analyse après une confirmation explicite", async ({ page }) => {
        await mockVerification(page, [verified]);
        await mockReport(page, { status: 200, json: { report: sampleReport } });
        await openVerification(page);
        await page.getByLabel("Nom de domaine").fill("bücher.aegis-test.fr");
        await page.getByLabel("Nom de domaine").press("Enter");
        await page.getByRole("button", { name: "Vérifier l'enregistrement" }).click();
        await expect(page.getByText("Propriété vérifiée")).toBeVisible();

        await page.getByRole("button", { name: "Lancer l'analyse" }).click();
        const dialog = page.getByRole("alertdialog");
        await expect(dialog).toContainText(`https://${challenge.domain}/`);
        await dialog.getByRole("button", { name: "Annuler" }).click();
        await expect(dialog).toBeHidden();

        await page.getByRole("button", { name: "Lancer l'analyse" }).click();
        await page.getByRole("alertdialog").getByRole("button", { name: "Lancer l'analyse" }).click();
        await expect(page).toHaveURL(new RegExp(`/rapport/${reportId}$`));
        await expect(page.getByRole("heading", { level: 1 })).toHaveText(sampleReport.displayDomain);

        await page.getByRole("link", { name: "Retour à la vérification" }).click();
        await expect(page.getByText("Propriété vérifiée")).toBeVisible();
        await page.getByRole("button", { name: "Vérifier un autre domaine" }).click();
        await expect(page.getByLabel("Nom de domaine")).toBeVisible();
    });
});

test.describe("rapport", () => {
    test("affiche le résumé, les sections et exporte le JSON localement", async ({ page }) => {
        await mockReport(page, { status: 200, json: { report: sampleReport } });
        await page.goto(`/rapport/${reportId}`);
        await expect(page.getByRole("img", { name: `Score indicatif : ${sampleReport.score.value} sur 100` })).toBeVisible();
        await expect(page.getByText("Problèmes importants")).toBeVisible();

        const firstRecommendation = page.getByRole("tabpanel").getByRole("button").first();
        await firstRecommendation.click();
        await expect(firstRecommendation).toHaveAttribute("aria-expanded", "true");

        await page.getByRole("tab", { name: "Cookies" }).click();
        await expect(page.getByRole("rowheader", { name: /session_id/ })).toBeVisible();
        await expect(page.getByText("valeur-fictive")).toHaveCount(0);

        await page.getByRole("tab", { name: "CSP" }).click();
        await expect(page.getByRole("heading", { name: "Politique 1" })).toBeVisible();

        const download = page.waitForEvent("download");
        await page.getByRole("button", { name: "Exporter en JSON" }).click();
        const file = await download;
        expect(file.suggestedFilename()).toBe("aegis-mon-site.example-2026-10-01.json");
        const content = JSON.parse(await (await file.createReadStream()).toArray().then((chunks) => Buffer.concat(chunks).toString("utf8")));
        expect(content).toMatchObject({ domain: sampleReport.domain, score: sampleReport.score });
    });

    test("imprime un rapport lisible et complet, même en thème sombre", async ({ page }) => {
        await mockReport(page, { status: 200, json: { report: sampleReport } });
        await page.addInitScript(() => localStorage.setItem("theme", "dark"));
        await page.goto(`/rapport/${reportId}`);
        await expect(page.locator("html")).toHaveClass(/dark/);
        await expect(page.getByRole("heading", { level: 1 })).toHaveText(sampleReport.displayDomain);

        await page.emulateMedia({ media: "print" });
        await expect(page.locator("header.header")).toBeHidden();
        await expect(page.locator("footer.footer")).toBeHidden();
        await expect(page.getByRole("link", { name: "Aller au contenu principal" })).toBeHidden();
        await expect(page.getByRole("button", { name: "Exporter en JSON" })).toBeHidden();
        const colors = await page.evaluate(() => ({
            body: getComputedStyle(document.body).backgroundColor,
            title: getComputedStyle(document.querySelector("h1") as Element).color
        }));
        expect(colors).toEqual({ body: "rgb(255, 255, 255)", title: "rgb(4, 4, 4)" });
        await expect(page.getByRole("list", { name: "Recommandations détaillées" })).toBeVisible();
        await expect(page.getByRole("button", { name: "Comment le score est calculé" })).toBeHidden();
        await expect(page.getByRole("heading", { name: "Cookies", exact: true })).toBeVisible();
    });

    test("ne déborde jamais horizontalement, même avec les tableaux", async ({ page }) => {
        await mockReport(page, { status: 200, json: { report: sampleReport } });
        await page.goto(`/rapport/${reportId}`);
        for (const tab of ["Recommandations", "En-têtes", "Cookies", "CSP"]) {
            await page.getByRole("tab", { name: new RegExp(`^${tab}`) }).click();
            const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
            expect(overflow, tab).toBeLessThanOrEqual(0);
        }
    });

    test("permet de parcourir les onglets au clavier", async ({ page, isMobile }) => {
        test.skip(isMobile, "Navigation au clavier testée sur ordinateur");
        await mockReport(page, { status: 200, json: { report: sampleReport } });
        await page.goto(`/rapport/${reportId}`);
        await page.getByRole("tab", { name: /Recommandations/ }).focus();
        await page.keyboard.press("ArrowRight");
        await expect(page.getByRole("tab", { name: "HTTPS et TLS" })).toBeFocused();
        await page.keyboard.press("Enter");
        await expect(page.getByRole("tab", { name: "HTTPS et TLS" })).toHaveAttribute("aria-selected", "true");
        await expect(page.getByText("Protocole négocié")).toBeVisible();
    });

    test("affiche un état de chargement", async ({ page }) => {
        await mockReport(page, { status: 200, json: { report: sampleReport } }, 1_500);
        await page.goto(`/rapport/${reportId}`);
        await expect(page.getByRole("status", { name: "Chargement du rapport" })).toBeVisible();
        await expect(page.getByRole("heading", { level: 1 })).toHaveText(sampleReport.displayDomain);
    });

    test("affiche un état vide pour un rapport expiré", async ({ page }) => {
        await mockReport(page, { status: 404, json: { error: "Rapport introuvable ou expiré." } });
        await page.goto(`/rapport/${reportId}`);
        await expect(page.getByRole("heading", { level: 1 })).toHaveText("Rapport introuvable");
    });

    test("affiche un état d'erreur sans détail technique", async ({ page }) => {
        await mockReport(page, { status: 502, json: { error: "L'analyse n'a pas pu aboutir." } });
        await page.goto(`/rapport/${reportId}`);
        await expect(page.getByRole("heading", { level: 1 })).toHaveText("Chargement impossible");
        await expect(page.getByText("L'analyse n'a pas pu aboutir.").first()).toBeVisible();
    });

    test("rejette une réponse non conforme au schéma", async ({ page }) => {
        await mockReport(page, { status: 200, json: { report: { ...sampleReport, score: { value: 900 } } } });
        await page.goto(`/rapport/${reportId}`);
        await expect(page.getByRole("heading", { level: 1 })).toHaveText("Chargement impossible");
    });
});

test.describe("interface", () => {
    test("bascule entre thème clair et sombre et mémorise le choix", async ({ page }) => {
        await page.emulateMedia({ colorScheme: "light" });
        await page.goto("/");
        const switcher = page.getByRole("switch", { name: "Thème sombre" });
        await expect(page.locator("html")).not.toHaveClass(/dark/);
        await switcher.click();
        await expect(page.locator("html")).toHaveClass(/dark/);
        await expect(switcher).toHaveAttribute("aria-checked", "true");
        await page.reload();
        await expect(page.locator("html")).toHaveClass(/dark/);
    });

    test("propose un lien d'évitement et un focus visible au clavier", async ({ page, isMobile }) => {
        test.skip(isMobile, "Navigation au clavier testée sur ordinateur");
        await page.goto("/verifier");
        await page.keyboard.press("Tab");
        const skipLink = page.getByRole("link", { name: "Aller au contenu principal" });
        await expect(skipLink).toBeFocused();
        await page.keyboard.press("Enter");
        await expect(page.locator("main")).toBeFocused();
        await page.getByLabel("Nom de domaine").focus();
        const outline = await page.getByLabel("Nom de domaine").evaluate((element) => getComputedStyle(element).boxShadow);
        expect(outline).not.toBe("none");
    });

    test("ouvre la navigation sur mobile", async ({ page, isMobile }) => {
        test.skip(!isMobile, "Menu propre au mobile");
        await page.goto("/");
        const toggle = page.getByRole("button", { name: "Menu de navigation" });
        await toggle.click();
        await expect(toggle).toHaveAttribute("aria-expanded", "true");
        const limits = page.getByRole("navigation", { name: "Navigation principale" }).getByRole("link", { name: "Limites" });
        await expect(limits).toBeVisible();
        await limits.click();
        await expect(toggle).toHaveAttribute("aria-expanded", "false");
        await expect(page.locator('#site-nav a[data-section="limites"]')).toHaveAttribute("aria-current", "true");
    });

    test("indique la section ou la page courante dans la navigation", async ({ page, isMobile }) => {
        test.skip(isMobile, "Indicateur visible dans la barre sur ordinateur");
        const navigation = page.getByRole("navigation", { name: "Navigation principale" });
        await page.goto("/");
        await expect(navigation.locator("[aria-current]")).toHaveCount(0);

        await page.locator("#controles h2").evaluate((element) => element.scrollIntoView({ block: "center" }));
        await expect(navigation.getByRole("link", { name: "Contrôles" })).toHaveAttribute("aria-current", "true");
        await expect(navigation.locator("[aria-current]")).toHaveCount(1);

        await navigation.getByRole("link", { name: "Fonctionnement" }).click();
        await expect(navigation.getByRole("link", { name: "Fonctionnement" })).toHaveAttribute("aria-current", "true");

        await page.goto("/verifier");
        await expect(navigation.getByRole("link", { name: "Vérifier un domaine" })).toHaveAttribute("aria-current", "page");
        await page.goto(`/rapport/${reportId}`);
        await expect(navigation.getByRole("link", { name: "Vérifier un domaine" })).toHaveAttribute("aria-current", "page");
    });

    test("respecte prefers-reduced-motion", async ({ page }) => {
        await page.emulateMedia({ reducedMotion: "reduce" });
        await page.goto("/");
        const duration = await page.locator(".hero__title").evaluate((element) => getComputedStyle(element).animationDuration);
        expect(Number.parseFloat(duration)).toBeLessThanOrEqual(0.01);
    });
});
