/**
 * The technician's phone (Playwright project `mobile`, 390×844): the pages used on call, with
 * the installed app's tab bar, in both themes, each checked with axe; and the PWA plumbing
 * (manifest, service worker).
 */
import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { mockApi } from './mock';

const pages: [string, string][] = [
	['alerts', '/alerts'],
	['alert', '/alerts/al-5'],
	['tickets', '/tickets'],
	['ticket', '/tickets/t-1'],
	['time', '/time'],
	['account', '/account']
];

/** Pretends the app runs installed (display-mode: standalone), so the tab bar shows. */
async function installed(page: Page) {
	await page.addInitScript(() => {
		const real = window.matchMedia.bind(window);
		window.matchMedia = (q: string) => (q.includes('display-mode: standalone') ? ({ matches: true, media: q, addEventListener() {}, removeEventListener() {} } as unknown as MediaQueryList) : real(q));
	});
}

async function settle(page: Page) {
	await page.locator('h1').first().waitFor({ timeout: 30_000 });
	await expect(page.locator('[aria-busy="true"]')).toHaveCount(0, { timeout: 20_000 });
	await page.evaluate(() => document.fonts.ready);
	await page.waitForTimeout(250);
}

for (const theme of ['light', 'dark'] as const) {
	test.describe(theme, () => {
		test.use({ colorScheme: theme });
		for (const [name, path] of pages) {
			test(name, async ({ page }) => {
				await installed(page);
				await mockApi(page);
				await page.goto(path);
				await settle(page);
				await expect(page.getByRole('navigation', { name: 'App tabs' })).toBeVisible();
				// The viewport, as on the phone: the tab bar and sticky actions are fixed to it.
				await expect(page).toHaveScreenshot(`${theme}-mobile-${name}.png`);
				const r = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
				const problems = r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical').map((v) => `${v.id}: ${v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')}`);
				expect(problems, problems.join('\n')).toEqual([]);
			});
		}

		test('bottom bar', async ({ page }) => {
			await installed(page);
			await mockApi(page);
			await page.goto('/alerts');
			await settle(page);
			const bar = page.getByRole('navigation', { name: 'App tabs' });
			await expect(bar.getByRole('link', { name: /Alerts/ })).toHaveAttribute('aria-current', 'page');
			// Every target is at least 44 px tall.
			for (const box of await bar.locator('a, button').evaluateAll((els) => els.map((e) => e.getBoundingClientRect().height))) expect(box).toBeGreaterThanOrEqual(44);
			await expect(bar).toHaveScreenshot(`${theme}-mobile-bottom-bar.png`);
			await bar.getByRole('button', { name: 'More' }).click();
			await expect(page.getByRole('dialog', { name: 'Navigation' })).toBeVisible();
		});
	});
}

test('not installed: no tab bar', async ({ page }) => {
	await mockApi(page);
	await page.goto('/alerts');
	await settle(page);
	await expect(page.getByRole('navigation', { name: 'App tabs' })).toHaveCount(0);
});

test.describe('installable', () => {
	test.use({ serviceWorkers: 'allow' });

	test('the manifest parses and the service worker registers', async ({ page }) => {
		// The server builds the manifest (src/pwa.rs); this is its shape with the built-in branding.
		await page.route('**/manifest.webmanifest', (route) =>
			route.fulfill({
				contentType: 'application/manifest+json',
				body: JSON.stringify({
					id: '/', name: 'Northwind IT RMM', short_name: 'Northwind IT', start_url: '/alerts?source=pwa', scope: '/', display: 'standalone', theme_color: '#0c1b21', background_color: '#0c1b21',
					icons: [
						{ src: '/icons/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
						{ src: '/icons/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
						{ src: '/icons/maskable-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' }
					]
				})
			})
		);
		await mockApi(page);
		await page.goto('/alerts');
		await settle(page);
		const cdp = await page.context().newCDPSession(page);
		const m = (await cdp.send('Page.getAppManifest')) as { url: string; errors: { message: string }[]; data?: string };
		expect(m.url).toMatch(/\/manifest\.webmanifest$/);
		expect(m.errors).toEqual([]);
		for (const icon of ['/icons/icon-192.png', '/icons/icon-512.png', '/icons/maskable-512.png', '/icons/apple-touch-icon.png', '/offline.html']) {
			expect((await page.request.get(icon)).status(), icon).toBe(200);
		}
		const active = await page.evaluate(() => navigator.serviceWorker.ready.then((r) => !!r.active));
		expect(active).toBe(true);
		await expect(page.locator('meta[name="theme-color"]')).toHaveAttribute('content', '#0c1b21');
	});
});
