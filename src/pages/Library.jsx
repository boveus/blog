import { useState, useCallback } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import Lightbox from '../components/Lightbox.jsx'
import FilterBar from '../components/FilterBar.jsx'
import useGallery from '../hooks/useGallery.js'

const base = import.meta.env.BASE_URL
const descriptions = {
  macro: { eyebrow: 'A closer look', title: 'Small worlds.', text: 'Arthropods, hidden textures, and the extraordinary details right under our feet.', cover: 'photos/macro/bugs/joro-spiders/joro_3.webp' },
  georgia: { eyebrow: 'Close to home', title: 'Georgia.', text: 'Quiet water, familiar landscapes, and moments close to home.', cover: 'photos/georgia/img_8656.webp' },
  peru: { eyebrow: 'A journey through Peru', title: 'Farther afield.', text: 'Into the mountains, over high passes, and through the places in between.', cover: 'photos/peru/macchu-picchu/img_7975.webp' },
}

export default function Library() {
  const [params, setParams] = useSearchParams()
  const collection = params.get('collection') || ''
  const category = params.get('category') || 'All'
  const query = params.get('q') || ''
  const { collections, selected, filteredPhotos, categories, isLoading, error } = useGallery(query, category, collection)
  const [lightboxIndex, setLightboxIndex] = useState(null)
  const [limit, setLimit] = useState(36)
  const close = useCallback(() => setLightboxIndex(null), [])
  const next = useCallback(() => setLightboxIndex(i => (i + 1) % filteredPhotos.length), [filteredPhotos.length])
  const prev = useCallback(() => setLightboxIndex(i => (i - 1 + filteredPhotos.length) % filteredPhotos.length), [filteredPhotos.length])
  function filter(key, value) {
    const updated = new URLSearchParams(params)
    if (!value || value === 'All') updated.delete(key)
    else updated.set(key, value)
    setParams(updated, { replace: key === 'q' })
    setLimit(36)
    close()
  }
  if (isLoading) return <div className="loading-state" role="status">Opening the photo library…</div>
  if (error) return <div className="gallery-empty" role="alert"><h1>The library couldn’t load.</h1><p>Please check your connection and try again.</p><button onClick={() => window.location.reload()}>Try again</button></div>

  return <div>
    {!selected ? <>
      <section className="editorial-intro">
        <p className="eyebrow">Brandon Stewart / Photography</p>
        <h1>A little closer.<br /><em>A little farther.</em></h1>
        <div className="intro-bottom"><p>From the small worlds at our feet to the mountains of Peru.<br />Photographs from wherever curiosity leads.</p><span className="edition">Explore the collections ↙</span></div>
      </section>
      <section className="collection-grid" aria-label="Photography collections">
        {collections.map((c, i) => {
          const d = descriptions[c.slug] || { title: c.name, text: '', eyebrow: 'Collection' }
          return <Link className={`collection-card${c.slug === 'georgia' ? ' collection-card--secondary' : ''}`} key={c.slug} to={`/?collection=${c.slug}`}>
            <img src={base + (d.cover || c.allPhotos[0].src)} alt={`${c.name} photography collection`} fetchPriority={i === 0 ? 'high' : 'auto'} />
            <div className="collection-top"><span>0{i + 1} / {c.name}</span><span>{c.allPhotos.length} photographs</span></div>
            <div className="collection-content"><p className="eyebrow">{d.eyebrow}</p><h2>{d.title}</h2><p>{d.text}</p><span className="collection-action">Explore {c.name} <span aria-hidden="true">↗</span></span></div>
          </Link>
        })}
      </section>
      <section className="about-strip"><div><p className="eyebrow">Behind the camera</p><h2>Hi, I’m Brandon.</h2></div><div><p>Software engineer, product security engineer, and photographer. I’m drawn to the intricate details of the natural world, whether close to home or a long way from it.</p><div className="social-links"><a href="https://github.com/boveus">GitHub ↗</a><a href="https://www.linkedin.com/in/brandon-scott-stewart/">LinkedIn ↗</a><a href="mailto:me@brandonsstewart.com">Email ↗</a></div></div></section>
    </> : <>
      <Link className="back-link" to="/">← All collections</Link>
      <section className="collection-heading"><div><p className="eyebrow">{descriptions[collection]?.eyebrow || 'Photography'}</p><h1>{selected.name}<em> /</em></h1></div><p>{descriptions[collection]?.text}<span>{selected.allPhotos.length} photographs · {categories.length - 1} {collection === 'peru' ? 'chapters' : collection === 'georgia' ? 'gallery' : 'subjects'}</span></p></section>
      <nav className="collection-switch" aria-label="Switch collection">{collections.map(c => <Link aria-current={c.slug === collection ? 'page' : undefined} key={c.slug} to={`/?collection=${c.slug}`} onClick={() => { close(); setLimit(36) }}>{c.name} <span>{c.allPhotos.length}</span></Link>)}</nav>
      <section className="gallery-section" aria-label={`${selected.name} photographs`}>
        <FilterBar categories={categories} activeCategory={category} onCategoryChange={v => filter('category', v)} searchQuery={query} onSearchChange={v => filter('q', v)} resultCount={filteredPhotos.length} />
        <div className={`photo-grid${collection === 'macro' ? ' photo-grid--balanced' : collection === 'georgia' ? ' photo-grid--georgia' : ''}`}>
          {filteredPhotos.slice(0, limit).map((photo, index) => <button key={photo.src} style={{ '--photo-ratio': photo.width && photo.height ? photo.width / photo.height : 1.5 }} className="photo-card" onClick={() => setLightboxIndex(index)} type="button" aria-label={`View ${photo.caption || photo.alt}`}>
            <img src={base + (photo.thumbnail || photo.src)} alt={photo.alt || photo.caption || ''} width={photo.width} height={photo.height} loading="lazy" decoding="async" />
            <div className="photo-info"><span className="photo-caption">{photo.caption}</span>{photo.species && <span className="photo-species">{photo.species}</span>}<span className="photo-category-label">{photo.category}</span></div>
          </button>)}
        </div>
        {!filteredPhotos.length && <div className="gallery-empty"><p>No photos match your search.</p><button onClick={() => { setParams({ collection }); setLimit(36) }}>Clear filters</button></div>}
        {filteredPhotos.length > limit && <div className="load-more"><p>Showing {limit} of {filteredPhotos.length} photographs</p><button onClick={() => setLimit(n => n + 36)}>Show more photographs ↓</button></div>}
      </section>
    </>}
    {lightboxIndex !== null && filteredPhotos[lightboxIndex] && <Lightbox photos={filteredPhotos} currentIndex={lightboxIndex} onClose={close} onNext={next} onPrev={prev} />}
  </div>
}
