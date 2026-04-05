#!/usr/bin/env node

import { readFileSync, writeFileSync, readdirSync, statSync } from "fs";
import { resolve, dirname, relative, extname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = resolve(__dirname, "../public");
const LIBRARY_PATH = resolve(PUBLIC_DIR, "library.json");
const PHOTOS_DIR = resolve(PUBLIC_DIR, "photos");

const PHOTO_EXTENSIONS = new Set([".webp", ".jpg", ".jpeg", ".png", ".gif", ".avif"]);

function loadLibrary() {
  return JSON.parse(readFileSync(LIBRARY_PATH, "utf-8"));
}

function saveLibrary(data) {
  writeFileSync(LIBRARY_PATH, JSON.stringify(data, null, 2) + "\n");
}

/** Convert a slug like "joro-spiders" to a display name like "Joro Spiders" */
function slugToName(slug) {
  return slug
    .split("-")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

/**
 * Recursively scan a directory and return a tree structure:
 * { dirs: { [name]: subtree }, files: [filename, ...] }
 */
function scanDir(dir) {
  const result = { dirs: {}, files: [] };
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    return result;
  }
  for (const entry of entries.sort()) {
    const fullPath = resolve(dir, entry);
    const stat = statSync(fullPath);
    if (stat.isDirectory()) {
      result.dirs[entry] = scanDir(fullPath);
    } else if (PHOTO_EXTENSIONS.has(extname(entry).toLowerCase())) {
      result.files.push(entry);
    }
  }
  return result;
}

/**
 * Find or create a category node by slug within a parent node.
 */
function findOrCreateCategory(parent, slug) {
  if (!parent.categories) parent.categories = [];
  let cat = parent.categories.find((c) => c.slug === slug);
  if (!cat) {
    cat = { name: slugToName(slug), slug, categories: [], photos: [] };
    parent.categories.push(cat);
    return { node: cat, created: true };
  }
  if (!cat.photos) cat.photos = [];
  if (!cat.categories) cat.categories = [];
  return { node: cat, created: false };
}

/**
 * Recursively sync the directory tree into the library tree.
 * Returns { added: string[], removedPhotos: string[], createdCategories: string[] }
 */
function syncTree(node, dirTree, pathPrefix) {
  const added = [];
  const removed = [];
  const createdCategories = [];

  // --- Sync photos in the current directory ---
  if (!node.photos) node.photos = [];
  const existingSrcs = new Set(node.photos.map((p) => p.src));

  // Add new photo files
  for (const file of dirTree.files) {
    const src = `${pathPrefix}/${file}`;
    if (!existingSrcs.has(src)) {
      node.photos.push({ src, alt: "", caption: "", species: "", location: "", description: "" });
      added.push(src);
    }
  }

  // Remove photos whose files no longer exist on disk
  const diskFiles = new Set(dirTree.files.map((f) => `${pathPrefix}/${f}`));
  const before = node.photos.length;
  const keptPhotos = [];
  for (const photo of node.photos) {
    if (diskFiles.has(photo.src)) {
      keptPhotos.push(photo);
    } else {
      removed.push(photo.src);
    }
  }
  node.photos = keptPhotos;

  // --- Recurse into subdirectories ---
  for (const [dirName, subtree] of Object.entries(dirTree.dirs)) {
    const { node: childNode, created } = findOrCreateCategory(node, dirName);
    if (created) {
      createdCategories.push(`${pathPrefix}/${dirName}`);
    }
    const childResult = syncTree(childNode, subtree, `${pathPrefix}/${dirName}`);
    added.push(...childResult.added);
    removed.push(...childResult.removed);
    createdCategories.push(...childResult.createdCategories);
  }

  return { added, removed, createdCategories };
}

function main() {
  const library = loadLibrary();
  const diskTree = scanDir(PHOTOS_DIR);

  console.log("Scanning photos directory...\n");

  const { added, removed, createdCategories } = syncTree(library, diskTree, "photos");

  if (createdCategories.length) {
    console.log(`📁 Created ${createdCategories.length} new category(s):`);
    createdCategories.forEach((c) => console.log(`   + ${c}`));
    console.log();
  }

  if (added.length) {
    console.log(`📸 Added ${added.length} new photo(s):`);
    added.forEach((p) => console.log(`   + ${p}`));
    console.log();
  }

  if (removed.length) {
    console.log(`🗑  Removed ${removed.length} stale photo(s):`);
    removed.forEach((p) => console.log(`   - ${p}`));
    console.log();
  }

  if (!added.length && !removed.length && !createdCategories.length) {
    console.log("✅ library.json is already up to date — nothing to do.");
    return;
  }

  saveLibrary(library);
  console.log(`✅ Saved updated library to ${relative(process.cwd(), LIBRARY_PATH)}`);
}

main();
