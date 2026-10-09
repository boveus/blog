import sharp from 'sharp'
import { readdir, mkdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'

// Originals are read only. Re-running replaces generated copies and preserves metadata.
const rotations = JSON.parse(await readFile(new URL('./peru-orientation.json', import.meta.url), 'utf8'))
const source = path.resolve(process.argv[2] || '../peru_final')
const publicDir = path.resolve('public')
const library = JSON.parse(await readFile(path.join(publicDir, 'library.json'), 'utf8'))
const folders = [
  ['1_approach', 'The approach'], ['2_into_mountains', 'Into the mountains'],
  ['3_lake_lazuna', 'Lake Lazuna'], ['4_high_passes', 'High passes'],
  ['5_descent', 'The descent'], ['6_aquas_calientes', 'Aguas Calientes'],
  ['7_macchu_picchu', 'Machu Picchu'], ['8_cusco', 'Cusco'],
  ['9_palccoyo', 'Palccoyo'], ['keeper_not_book', 'Miscellaneous'],
]
const macro = library.categories.find(c => c.slug === 'macro')
const existingPeru = library.categories.find(c => c.slug === 'peru')
async function importFolder(folder, name, prefix, old) {
  const files = (await readdir(path.join(source, folder))).filter(f => /\.jpe?g$/i.test(f)).sort()
  const photos = []
  await mkdir(path.join(publicDir, prefix), { recursive: true })
  for (const [index, file] of files.entries()) {
    const stem = path.parse(file).name.toLowerCase()
    const src = `${prefix}/${stem}.webp`
    const thumbnail = `thumbnails/${prefix}/${stem}.webp`
    await mkdir(path.dirname(path.join(publicDir, thumbnail)), { recursive: true })
    const input = path.join(source, folder, file)
    const rotation = rotations[`${folder}/${file}`] || 0
    const info = await sharp(input, { autoOrient: true }).rotate(rotation).resize({ width: 2400, height: 2400, fit: 'inside', withoutEnlargement: true }).webp({ quality: 84 }).toFile(path.join(publicDir, src))
    await sharp(input, { autoOrient: true }).rotate(rotation).resize({ width: 800, height: 800, fit: 'inside', withoutEnlargement: true }).webp({ quality: 78 }).toFile(path.join(publicDir, thumbnail))
    const previous = old?.photos?.find(p => p.src === src)
    photos.push({ alt: `${name}, Peru — photograph ${index + 1}`, caption: `${name} · ${String(index + 1).padStart(2, '0')}`, location: 'Peru', ...previous, src, thumbnail, width: info.width, height: info.height, originalFile: `${folder}/${file}` })
  }
  console.log(`${name}: ${photos.length}`)
  return { name, slug: prefix.split('/').at(-1), categories: [], photos }
}
const peru = { name: 'Peru', slug: 'peru', categories: [], photos: [] }
for (const [folder, name] of folders) {
  const slug = folder === 'keeper_not_book' ? 'miscellaneous' : folder.replace(/^\d+_/, '').replaceAll('_', '-')
  peru.categories.push(await importFolder(folder, name, `photos/peru/${slug}`, existingPeru?.categories.find(c => c.slug === slug)))
}
const tripMacro = await importFolder('keeper_not_book/10_macro_shots', 'Peru macro', 'photos/macro/peru-macro', macro.categories.find(c => c.slug === 'peru-macro'))
macro.categories = [...macro.categories.filter(c => c.slug !== 'peru-macro'), tripMacro]
library.categories = [...library.categories.filter(c => c.slug !== 'peru'), peru]
await writeFile(path.join(publicDir, 'library.json'), JSON.stringify(library, null, 2) + '\n')
