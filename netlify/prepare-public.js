const fs = require('fs/promises');
const path = require('path');

const rootDir = path.resolve(__dirname, '..');
const distDir = path.join(rootDir, 'dist');

async function copyPublicFiles() {
  await fs.rm(distDir, { recursive: true, force: true });
  await fs.mkdir(distDir, { recursive: true });

  await fs.copyFile(path.join(rootDir, 'index.html'), path.join(distDir, 'index.html'));
  await fs.cp(path.join(rootDir, 'front-end'), path.join(distDir, 'front-end'), { recursive: true });
}

copyPublicFiles().catch((error) => {
  console.error(error);
  process.exit(1);
});
