// Minimal Docusaurus config scaffold for serving the repository docs from
// ../docs without relocating the application source tree.
module.exports = {
  title: 'Argus',
  tagline: 'Network discovery, inventory, topology, and fingerprinting',
  url: 'https://joelmale.github.io',
  baseUrl: '/argus/',
  favicon: 'img/favicon.svg',
  organizationName: 'joelmale',
  projectName: 'argus',
  onBrokenLinks: 'throw',
  trailingSlash: false,
  markdown: {
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },
  themeConfig: {
    navbar: {
      title: 'Argus Docs',
      items: [
        {
          to: '/',
          label: 'Docs Home',
          position: 'left',
        },
        {
          type: 'docSidebar',
          sidebarId: 'docs',
          position: 'left',
          label: 'Documentation',
        },
        {
          href: 'https://github.com/joelmale/argus',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            { label: 'Introduction', to: '/' },
            { label: 'Getting Started', to: '/getting-started' },
          ],
        },
        {
          title: 'Project',
          items: [
            { label: 'Docs Site', href: 'https://joelmale.github.io/argus/' },
            { label: 'Main README', href: 'https://github.com/joelmale/argus/blob/main/README.md' },
          ],
        },
      ],
    },
  },
  presets: [
    [
      'classic',
      {
        docs: {
          path: '../docs',
          routeBasePath: '/',
          sidebarPath: require.resolve('./sidebars.js'),
        },
        blog: false,
        pages: false,
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      },
    ],
  ],
  themes: ['@docusaurus/theme-mermaid'],
};
