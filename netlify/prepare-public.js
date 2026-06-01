const fs = require('fs/promises');
const path = require('path');

const rootDir = path.resolve(__dirname, '..');
const distDir = path.join(rootDir, 'dist');
const fontAwesomeDir = path.join(rootDir, 'node_modules', '@fortawesome', 'fontawesome-free');

async function copyPublicFiles() {
  await fs.rm(distDir, { recursive: true, force: true });
  await fs.mkdir(distDir, { recursive: true });

  await fs.copyFile(path.join(rootDir, 'index.html'), path.join(distDir, 'index.html'));
  await fs.cp(path.join(rootDir, 'front-end'), path.join(distDir, 'front-end'), { recursive: true });

  try {
    await fs.access(fontAwesomeDir);
    await fs.cp(
      path.join(fontAwesomeDir, 'css'),
      path.join(distDir, 'assets', 'fontawesome', 'css'),
      { recursive: true }
    );
    await fs.cp(
      path.join(fontAwesomeDir, 'webfonts'),
      path.join(distDir, 'assets', 'fontawesome', 'webfonts'),
      { recursive: true }
    );
  } catch (_error) {
    console.warn('Font Awesome local non installé: copie ignorée pour ce build local.');
  }
}

copyPublicFiles().catch((error) => {
  console.error(error);
  process.exit(1);
});
