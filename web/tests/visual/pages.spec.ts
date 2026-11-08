import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { mockApi } from './mock';

const pages: [string, string][] = [
	['dashboard', '/'],
	['dashboard-client', '/?client=c-acme'],
	['agents', '/agents'],
	['agents-attention', '/agents?view=attention'],
	['agent', '/agents/a-3'],
	['agent-inventory', '/agents/a-3?tab=inventory'],
	['agent-software', '/agents/a-3?tab=software'],
	['agent-jobs', '/agents/a-3?tab=jobs'],
	['agent-activity', '/agents/a-1?tab=activity'],
	['jobs', '/jobs'],
	['job', '/jobs/j-1'],
	['clients', '/clients'],
	['client', '/clients/c-acme'],
	['client-sites', '/clients/c-acme?tab=sites'],
	['scripts', '/scripts'],
	['script', '/scripts/s-spool'],
	['audit', '/audit'],
	['settings', '/settings'],
	['users', '/settings/users'],
	['account', '/account']
];
const phone: [string, string][] = [
	['dashboard', '/'],
	['agents', '/agents'],
	['agent', '/agents/a-3'],
	['job', '/jobs/j-1']
];

/** Waits until nothing is loading: no skeletons, fonts in, lazy editors mounted. */
async function settle(page: Page) {
	// Every page has an h1 once the app has mounted; before that the page is empty.
	await page.locator('h1').first().waitFor({ timeout: 30_000 });
	// The gallery shows loading states on purpose.
	if (!page.url().includes('/dev/ui')) await expect(page.locator('[aria-busy="true"]')).toHaveCount(0, { timeout: 20_000 });
	await page.evaluate(() => document.fonts.ready);
	if (await page.locator('#s-body, #rs-body').count()) await page.locator('.cm-editor').first().waitFor();
	await page.waitForTimeout(250);
}

for (const theme of ['light', 'dark'] as const) {
	test.describe(theme, () => {
		test.use({ colorScheme: theme });

		for (const [name, path] of pages) {
			test(name, async ({ page }) => {
				await mockApi(page);
				await page.goto(path);
				await settle(page);
				await expect(page).toHaveScreenshot(`${theme}-${name}.png`, { fullPage: true });
			});
		}

		test('gallery', async ({ page }) => {
			await mockApi(page, { signedIn: false });
			await page.goto('/dev/ui');
			await page.getByRole('heading', { name: 'UI gallery' }).waitFor();
			await settle(page);
			await expect(page).toHaveScreenshot(`${theme}-gallery.png`, { fullPage: true });
		});

		test('login', async ({ page }) => {
			await mockApi(page, { signedIn: false });
			await page.goto('/login');
			await settle(page);
			await expect(page).toHaveScreenshot(`${theme}-login.png`);
		});

		test('command palette', async ({ page }) => {
			await mockApi(page);
			await page.goto('/agents');
			await settle(page);
			await page.keyboard.press('Control+k');
			const input = page.getByPlaceholder(/Search agents, clients, sites/);
			await expect(input).toBeFocused();
			await input.fill('acme');
			await expect(page.getByRole('option', { name: /acme-dc01/ })).toBeVisible();
			await expect(page).toHaveScreenshot(`${theme}-palette.png`);
		});

		test('confirm dialog', async ({ page }) => {
			await mockApi(page);
			await page.goto('/clients/c-acme');
			await settle(page);
			await page.getByRole('button', { name: 'More actions' }).click();
			await page.getByRole('menuitem', { name: 'Delete client…' }).click();
			await expect(page.getByRole('alertdialog')).toBeVisible();
			await expect(page.getByRole('button', { name: 'Delete client' })).toBeDisabled();
			await page.getByLabel('Type Acme Corp to confirm').fill('Acme Corp');
			await expect(page.getByRole('button', { name: 'Delete client' })).toBeEnabled();
			await expect(page).toHaveScreenshot(`${theme}-confirm.png`);
		});

		test.describe('phone', () => {
			test.use({ viewport: { width: 375, height: 812 }, isMobile: true, hasTouch: true });
			for (const [name, path] of phone) {
				test(name, async ({ page }) => {
					await mockApi(page);
					await page.goto(path);
					await settle(page);
					await expect(page).toHaveScreenshot(`${theme}-phone-${name}.png`, { fullPage: true });
				});
			}
			test('navigation drawer', async ({ page }) => {
				await mockApi(page);
				await page.goto('/agents');
				await settle(page);
				await page.getByRole('button', { name: 'Open navigation' }).click();
				await expect(page.getByRole('dialog', { name: 'Navigation' })).toBeVisible();
				await expect(page).toHaveScreenshot(`${theme}-phone-drawer.png`);
			});
		});

		// WCAG 2.2 AA checks (contrast, names, roles) on every page, in this theme.
		test('accessibility', async ({ page }) => {
			test.setTimeout(180_000);
			await mockApi(page);
			const problems: string[] = [];
			for (const [name, path] of [...pages, ['gallery', '/dev/ui'] as [string, string]]) {
				await page.goto(path);
				await settle(page);
				const r = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
				for (const v of r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')) {
					problems.push(`${name}: ${v.id} (${v.impact}): ${v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')}`);
				}
			}
			expect(problems, problems.join('\n')).toEqual([]);
		});
	});
}

test('keyboard: g a, j/k and Enter', async ({ page }) => {
	await mockApi(page);
	await page.goto('/');
	await settle(page);
	await page.keyboard.press('g');
	await page.keyboard.press('a');
	await expect(page).toHaveURL(/\/agents$/);
	await settle(page);
	await page.keyboard.press('j');
	await page.keyboard.press('j');
	await page.keyboard.press('Enter');
	await expect(page).toHaveURL(/\/agents\/a-/);
	await page.keyboard.press('?');
	await expect(page.getByRole('dialog', { name: 'Keyboard shortcuts' })).toBeVisible();
});

test('filters live in the URL', async ({ page }) => {
	await mockApi(page);
	await page.goto('/agents');
	await settle(page);
	await page.getByRole('tab', { name: /^Offline/ }).click();
	await expect(page).toHaveURL(/view=offline/);
	await page.getByRole('button', { name: 'Hostname' }).click();
	await expect(page).toHaveURL(/sort=hostname&dir=desc|dir=desc/);
	await page.reload();
	await expect(page.getByRole('tab', { name: /^Offline/ })).toHaveAttribute('aria-selected', 'true');
});
