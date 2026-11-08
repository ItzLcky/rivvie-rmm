import tailwindcss from '@tailwindcss/vite';
import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

// Dev: `npm run dev` proxies the API (and terminal WebSocket) to a local rmm-server.
const backend = process.env.RMM_BACKEND ?? 'http://127.0.0.1:8080';

export default defineConfig({
	plugins: [
		tailwindcss(),
		sveltekit({
			compilerOptions: {
				runes: ({ filename }) => (filename.split(/[/\\]/).includes('node_modules') ? undefined : true)
			},
			// Pure SPA: rmm-server serves build/ and falls back to 200.html for client routes.
			adapter: adapter({ fallback: '200.html' }),
			// Emitted as a <meta> tag with hashes of SvelteKit's inline bootstrap script, so no other
			// inline or third-party script runs. rmm-server's header CSP adds frame-ancestors (which a
			// meta tag can't carry); browsers enforce both policies. Styles stay 'unsafe-inline':
			// Svelte transitions and xterm.js inject <style> elements and style attributes.
			csp: {
				mode: 'hash',
				directives: {
					'default-src': ['self'],
					'script-src': ['self'],
					'style-src': ['self', 'unsafe-inline'],
					'img-src': ['self', 'data:', 'blob:'],
					'font-src': ['self'],
					'connect-src': ['self'],
					'object-src': ['none'],
					'base-uri': ['self'],
					'form-action': ['self']
				}
			}
		})
	],
	build: {
		// Fonts are always separate files: the CSP's font-src 'self' rejects inlined data: URIs.
		assetsInlineLimit: (file) => (file.endsWith('.woff2') || file.endsWith('.woff') ? false : undefined)
	},
	server: {
		proxy: { '/api': { target: backend, ws: true, changeOrigin: false } }
	}
});
