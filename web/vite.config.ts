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
			adapter: adapter({ fallback: '200.html' })
		})
	],
	server: {
		proxy: { '/api': { target: backend, ws: true, changeOrigin: false } }
	}
});
