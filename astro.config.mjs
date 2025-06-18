// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	site: 'https://f1r3ch0.github.io/',
	base: 'f1r3ch0',
	integrations: [
		starlight({
			title: 'F1r3ch0',
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/withastro/starlight' }],
			sidebar: [
				{
					label: '2025',
					items: [
						// Each item here is one entry in the navigation menu.
						{ label: 'TJCTF 2025', autogenerate: { directory: 'year-2025/tjctf'} },
						{ label: 'SmileyCTF 2025', autogenerate: { directory: 'year-2025/SmileyCTF'} },
					],
				},
			],
		}),
	],
});
