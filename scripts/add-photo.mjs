#!/usr/bin/env node

import { readFileSync, writeFileSync } from "fs";
import { createInterface } from "readline";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const LIBRARY_PATH = resolve(__dirname, "../public/library.json");

const rl = createInterface({ input: process.stdin, output: process.stdout });
const ask = (q) => new Promise((r) => rl.question(q, r));

function loadLibrary() {
  return JSON.parse(readFileSync(LIBRARY_PATH, "utf-8"));
}

function saveLibrary(data) {
  writeFileSync(LIBRARY_PATH, JSON.stringify(data, null, 2) + "\n");
}

/** Flatten category tree into a list of { path, node } for display */
function flattenCategories(categories, prefix = "") {
  const result = [];
  for (const cat of categories) {
    const path = prefix ? `${prefix} > ${cat.name}` : cat.name;
    result.push({ path, node: cat });
    if (cat.categories?.length) {
      result.push(...flattenCategories(cat.categories, path));
    }
  }
  return result;
}

async function pickCategory(library) {
  const flat = flattenCategories(library.categories);

  console.log("\nCategories:");
  console.log("  0) [root level]");
  flat.forEach((c, i) => console.log(`  ${i + 1}) ${c.path}`));
  console.log(`  n) Create a new category`);

  const choice = await ask("\nAdd photo to which category? ");

  if (choice === "n" || choice === "N") {
    return await createCategory(library, flat);
  }

  const idx = parseInt(choice, 10);
  if (idx === 0) return library;
  if (idx >= 1 && idx <= flat.length) return flat[idx - 1].node;

  console.log("Invalid choice, using root.");
  return library;
}

async function createCategory(library, flat) {
  console.log("\nWhere should the new category go?");
  console.log("  0) [root level]");
  flat.forEach((c, i) => console.log(`  ${i + 1}) ${c.path}`));

  const parentChoice = await ask("\nParent? ");
  const parentIdx = parseInt(parentChoice, 10);
  let parent;
  if (parentIdx === 0) {
    parent = library;
  } else if (parentIdx >= 1 && parentIdx <= flat.length) {
    parent = flat[parentIdx - 1].node;
  } else {
    console.log("Invalid choice, using root.");
    parent = library;
  }

  const name = await ask("Category name: ");
  const slugDefault = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
  const slug = (await ask(`Slug [${slugDefault}]: `)) || slugDefault;

  const newCat = { name, slug, categories: [], photos: [] };
  parent.categories.push(newCat);
  return newCat;
}

async function main() {
  const library = loadLibrary();
  const target = await pickCategory(library);

  console.log("\nFill in the photo details (press Enter to skip optional fields):\n");

  const src = await ask("  src (required, e.g. images/macro/photo.jpg): ");
  if (!src) {
    console.log("src is required. Aborting.");
    rl.close();
    process.exit(1);
  }

  const alt = await ask("  alt (optional): ");
  const caption = await ask("  caption (optional): ");

  const photo = { src };
  if (alt) photo.alt = alt;
  if (caption) photo.caption = caption;

  console.log("\nAdding:");
  console.log(JSON.stringify(photo, null, 2));

  const confirm = await ask("\nLook good? (Y/n) ");
  if (confirm && confirm.toLowerCase() === "n") {
    console.log("Aborted.");
    rl.close();
    process.exit(0);
  }

  target.photos.push(photo);
  saveLibrary(library);
  console.log(`\nSaved to ${LIBRARY_PATH}`);

  const again = await ask("Add another photo? (y/N) ");
  if (again && again.toLowerCase() === "y") {
    rl.close();
    return main();
  }

  rl.close();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
