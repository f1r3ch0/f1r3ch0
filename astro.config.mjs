// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	site: 'https://f1r3ch0.github.io/',
	base: '',
	integrations: [
		starlight({
			title: '',
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/withastro/starlight' }],
			sidebar: [
				{
					label: 'example',
					items: [
						// Each item here is one entry in the navigation menu.
						{ label: 'Example Guide', slug: 'guides/example' },
					],
				},
				{
					label: '2025',
					items: [
						// Each item here is one entry in the navigation menu.
						{ label: 'TJCTF 2025', autogenerate: { directory: 'year-2025/tjctf'} },
					],
				},
			],
		}),
	],
});
