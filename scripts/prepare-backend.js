const fs = require('fs');
const path = require('path');

// Function to copy directory recursively
function copyDirectory(src, dest) {
  if (!fs.existsSync(dest)) {
    fs.mkdirSync(dest, { recursive: true });
  }

  const entries = fs.readdirSync(src, { withFileTypes: true });

  for (let entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);

    if (entry.isDirectory()) {
      copyDirectory(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

// Create backend distribution directory
const distDir = path.join(__dirname, '../dist');
if (!fs.existsSync(distDir)) {
  fs.mkdirSync(distDir, { recursive: true });
}

// Copy necessary files to dist
const filesToCopy = [
  'server.js',
  'package.json',
  'pnpm-lock.yaml',
  '.env',
  '.env.local'
];

filesToCopy.forEach(file => {
  const srcPath = path.join(__dirname, '..', file);
  const destPath = path.join(distDir, file);
  if (fs.existsSync(srcPath)) {
    fs.copyFileSync(srcPath, destPath);
  }
});

// Copy API routes
const apiSrcDir = path.join(__dirname, '../app/api');
const apiDestDir = path.join(distDir, 'app/api');
copyDirectory(apiSrcDir, apiDestDir);

// Copy lib directory
const libSrcDir = path.join(__dirname, '../lib');
const libDestDir = path.join(distDir, 'lib');
copyDirectory(libSrcDir, libDestDir);

console.log('Backend files prepared for deployment.');