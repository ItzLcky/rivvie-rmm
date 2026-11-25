import { defineConfig, devices } from '@playwright/test';

/**
 * Visual regression and accessibility checks for the dashboard: every main page and the
 * /dev/ui gallery, in light and dark, against a mocked API (tests/visual/mock.ts) with a frozen
 * clock. Baselines are rendered in the Playwright Docker image so they match CI exactly:
 *
 *   npm run test:visual:docker              # compare
 *   npm run test:visual:docker -- --update-snapshots
 */
export default defineConfig({
	testDir: 'tests/visual',
	snapshotPathTemplate: '{testDir}/__screenshots__/{arg}{ext}',
	fullyParallel: true,
	forbidOnly: !!process.env.CI,
	retries: process.env.CI ? 1 : 0,
	reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
	timeout: 60_000,
	expect: { toHaveScreenshot: { maxDiffPixelRatio: 0.002, animations: 'disabled', caret: 'hide' } },
	// The service worker would sit between the page and the mocked API; only the PWA test lets it in.
	use: { baseURL: 'http://127.0.0.1:4173', trace: 'retain-on-failure', locale: 'en-US', timezoneId: 'UTC', serviceWorkers: 'block' },
	projects: [
		{ name: 'chromium', testIgnore: /mobile\.spec\.ts/, use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } } },
		// The technician's phone (docs/design/pwa.md): 390×844, touch, the installed app's tab bar.
		{ name: 'mobile', testMatch: /mobile\.spec\.ts/, use: { ...devices['Desktop Chrome'], viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true } }
	],
	webServer: {
		command: 'node node_modules/vite/bin/vite.js dev --port 4173 --strictPort --host 127.0.0.1',
		url: 'http://127.0.0.1:4173/login',
		reuseExistingServer: !process.env.CI,
		timeout: 120_000
	}
});
