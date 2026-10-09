import { useState, useEffect, useMemo } from 'react'

export function collectPhotos(node) {
  return [
    ...(node.photos || []).map(p => ({ ...p, category: node.name || 'Uncategorized' })),
    ...(node.categories || []).flatMap(collectPhotos),
  ]
}

export default function useGallery(searchQuery, activeCategory, collection) {
  const [library, setLibrary] = useState(null)
  const [error, setError] = useState(false)
  useEffect(() => {
    const controller = new AbortController()
    fetch(import.meta.env.BASE_URL + 'library.json', { signal: controller.signal })
      .then(r => { if (!r.ok) throw new Error('Unable to load photos'); return r.json() })
      .then(setLibrary)
      .catch(() => { if (!controller.signal.aborted) setError(true) })
    return () => controller.abort()
  }, [])
  const collections = useMemo(() => (library?.categories || [])
    .map(c => ({ ...c, allPhotos: collectPhotos(c) })).filter(c => c.allPhotos.length), [library])
  const selected = collections.find(c => c.slug === collection)
  const allPhotos = selected?.allPhotos || []
  const categories = ['All', ...new Set(allPhotos.map(p => p.category))]
  const q = searchQuery.trim().toLowerCase()
  const filteredPhotos = allPhotos.filter(p =>
    (activeCategory === 'All' || p.category === activeCategory) &&
    (!q || [p.caption, p.species, p.description, p.location, p.category, p.originalFile].some(v => v?.toLowerCase().includes(q))))
  return { collections, selected, filteredPhotos, categories, error, isLoading: library === null && !error }
}
