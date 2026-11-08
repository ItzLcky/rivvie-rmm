/**
 * Svelte action for a horizontally scrolling strip (tabs, views): fades the edge that has
 * more content, so a clipped label reads as "scrolls" rather than "truncated". The fade is
 * a mask driven by --fl / --fr (see .scroll-fade in layout.css).
 */
export function scrollFade(node: HTMLElement) {
	const update = () => {
		const max = node.scrollWidth - node.clientWidth;
		node.style.setProperty('--fl', node.scrollLeft > 1 ? '1.5rem' : '0px');
		node.style.setProperty('--fr', node.scrollLeft < max - 1 ? '1.5rem' : '0px');
	};
	node.addEventListener('scroll', update, { passive: true });
	const ro = new ResizeObserver(update);
	ro.observe(node);
	for (const c of node.children) ro.observe(c);
	update();
	return {
		destroy() {
			node.removeEventListener('scroll', update);
			ro.disconnect();
		}
	};
}
