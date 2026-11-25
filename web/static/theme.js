// Runs before first paint (a plain script, so the strict CSP's script-src 'self' allows it):
// applies the saved theme, density and branded accent so the page never flashes the wrong colours. The app
// (src/lib/theme.svelte.ts) takes over once loaded and keeps this localStorage copy in sync
// with the user's server-side preferences.
(function () {
	var d = document.documentElement;
	var theme = 'system';
	var density = 'compact';
	try {
		theme = localStorage.getItem('rmm.theme') || 'system';
		density = localStorage.getItem('rmm.density') || 'compact';
	} catch (e) {
		/* storage blocked: use the defaults */
	}
	var dark = theme === 'dark' || (theme !== 'light' && window.matchMedia('(prefers-color-scheme: dark)').matches);
	d.dataset.theme = dark ? 'dark' : 'light';
	d.dataset.density = density;
	// The branded accent palette (src/lib/branding.ts caches it), so it doesn't flash teal.
	try {
		var brand = JSON.parse(localStorage.getItem('rmm.brand') || 'null');
		if (brand && typeof brand === 'object') {
			for (var k in brand) {
				if (/^--brand-(light|dark)-[a-z-]+$/.test(k) && /^#[0-9a-f]{6}$/.test(brand[k])) d.style.setProperty(k, brand[k]);
			}
		}
	} catch (e) {
		/* nothing cached, or storage blocked */
	}
})();
