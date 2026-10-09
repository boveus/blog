import sharp from 'sharp'
import { readFile, writeFile, mkdir, readdir } from 'node:fs/promises'
import path from 'node:path'

const source = path.resolve(process.argv[2] || '../Desktop/untitled folder')
const library = JSON.parse(await readFile('public/library.json', 'utf8'))
const macro = library.categories.find(c => c.slug === 'macro')
const bugs = macro.categories.find(c => c.slug === 'bugs')
function category(parent, slug, name) {
  let node = parent.categories.find(c => c.slug === slug)
  if (!node) { node = { name, slug, categories: [], photos: [] }; parent.categories.push(node) }
  return node
}
const georgia = category(library, 'georgia', 'Georgia')
const fungi = category(macro, 'fungi', 'Fungi')
const worms = category(bugs, 'worms', 'Worms')
const ants = category(bugs, 'ants', 'Ants')
const selections = [
  ['8654', georgia, 'georgia', 'Pond Ripples', 'Waterfowl crossing a pond below reflections of trees.'],
  ['8656', georgia, 'georgia', 'At the Water’s Edge', 'A tree-lined pond with waterfowl and a sunlit grassy bank.'],
  ['8745', fungi, 'macro/fungi', 'Layered Mushroom Caps', 'Pale overlapping mushroom caps with delicate fringed edges.'],
  ['8750', fungi, 'macro/fungi', 'Mushroom Gills', 'Close view of pale mushroom gills spreading beneath overlapping caps.'],
  ['8754', worms, 'macro/bugs/worms', 'Worm in Decaying Wood', 'A smooth, segmented brown worm among fibers of decaying wood.'],
  ['8759', worms, 'macro/bugs/worms', 'Worm — Close View', 'A slender brown worm extending across the exposed interior of a log.'],
  ['8763', fungi, 'macro/fungi', 'Gills and Curled Edges', 'A pale mushroom viewed from below, showing branching gills and curled cap edges.'],
  ['8782', fungi, 'macro/fungi', 'Banded Shelf Fungus', 'A small bracket fungus with concentric bands growing from wood.'],
  ['8793', fungi, 'macro/fungi', 'Shelves of Fungi', 'Overlapping bands of shelf fungi running along decaying wood.'],
  ['8812', fungi, 'macro/fungi', 'Pleated Mushroom Cap', 'A delicate pale-yellow mushroom cap with fine radial pleats.'],
  ['8815', fungi, 'macro/fungi', 'Pleated Cap — Side View', 'A thin mushroom cap with radiating ridges above a slender stem.'],
  ['8822', fungi, 'macro/fungi', 'Cup-shaped Fungi', 'Two tan cup-shaped fungal growths among wood and moss.'],
  ['8823', fungi, 'macro/fungi', 'Fungi on Fallen Wood', 'Pale cup-shaped fungi clustered on a dark piece of wood.'],
  ['8826', fungi, 'macro/fungi', 'A Pair of Fungi', 'Two closely spaced tan fungal growths with pale, uneven rims.'],
  ['8845', fungi, 'macro/fungi', 'Pale Mushroom', 'A pale mushroom cap with a yellowish center and fine surface texture.'],
  ['8872', fungi, 'macro/fungi', 'Emerging Mushroom', 'A young mushroom with a textured gray-white cap emerging through leaf litter.'],
  ['8891', ants, 'macro/bugs/ants', 'Ant Beneath a Twig', 'A black ant clinging beneath a twig against a soft green background.'],
  ['8899', fungi, 'macro/fungi', 'Mushroom Cap Texture', 'An extreme close-up of raised scales on a pale mushroom cap.'],
  ['8900', fungi, 'macro/fungi', 'Scaly Mushroom Cap', 'A rounded pale mushroom cap covered in small pointed scales.'],
]
const files = (await readdir(source)).filter(f => /\.jpe?g$/i.test(f))
for (const [id, node, folder, caption, description] of selections) {
  const originalFile = `IMG_${id}.JPG`
  if (!files.includes(originalFile)) throw new Error(`Missing selected image: ${originalFile}`)
  const src = `photos/${folder}/img_${id}.webp`, thumbnail = `thumbnails/${src}`
  await mkdir(path.dirname('public/' + src), { recursive: true })
  await mkdir(path.dirname('public/' + thumbnail), { recursive: true })
  const input = path.join(source, originalFile)
  const info = await sharp(input, { autoOrient: true }).resize({ width: 2400, height: 2400, fit: 'inside', withoutEnlargement: true }).webp({ quality: 84 }).toFile('public/' + src)
  await sharp(input, { autoOrient: true }).resize({ width: 800, height: 800, fit: 'inside', withoutEnlargement: true }).webp({ quality: 78 }).toFile('public/' + thumbnail)
  const metadata = node === georgia ? {} : {
    species: node === fungi ? 'Fungi (species undetermined)' : node === ants ? 'Formicidae family (Ant; species undetermined)' : 'Worm (species undetermined)',
    identificationNote: 'Photo-based identification only; the species cannot be confirmed from this view.',
  }
  const previous = node.photos.find(p => p.src === src)
  const photo = { caption, alt: description, description, location: 'Georgia', ...metadata, ...previous, src, thumbnail, width: info.width, height: info.height, originalFile: `untitled-folder/${originalFile}` }
  if (previous) Object.assign(previous, photo)
  else node.photos.push(photo)
}
await writeFile('public/library.json', JSON.stringify(library, null, 2) + '\n')
console.log('Imported 17 macro photographs and 2 Georgia photographs. Originals unchanged.')
