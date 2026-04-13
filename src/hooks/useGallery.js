import { useState, useEffect, useMemo } from 'react'

function collectPhotosWithCategory(node) {
  const isLeaf = !node.categories || node.categories.length === 0
  const photos = (node.photos || []).map(p => ({
    ...p,
    category: node.name || 'Uncategorized'
  }))
  if (!isLeaf) {
    for (const cat of node.categories) {
      photos.push(...collectPhotosWithCategory(cat))
    }
  }
  return photos
}

export default function useGallery(searchQuery, activeCategory) {
  const [library, setLibrary] = useState(null)

  useEffect(() => {
    const controller = new AbortController()
    fetch(import.meta.env.BASE_URL + 'library.json?v=' + Date.now(), { signal: controller.signal })
      .then(r => r.json())
      .then(setLibrary)
      .catch(() => setLibrary({ categories: [], photos: [] }))
    return () => controller.abort()
  }, [])

  const allPhotos = useMemo(() => {
    if (!library) return []
    return collectPhotosWithCategory(library)
  }, [library])

  const categories = useMemo(() => {
    const names = [...new Set(allPhotos.map(p => p.category))].sort()
    return ['All', ...names]
  }, [allPhotos])

  const filteredPhotos = useMemo(() => {
    let result = allPhotos

    if (activeCategory && activeCategory !== 'All') {
      result = result.filter(p => p.category === activeCategory)
    }

    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      result = result.filter(p =>
        (p.caption || '').toLowerCase().includes(q) ||
        (p.species || '').toLowerCase().includes(q) ||
        (p.description || '').toLowerCase().includes(q) ||
        (p.location || '').toLowerCase().includes(q) ||
        (p.category || '').toLowerCase().includes(q)
      )
    }

    return result
  }, [allPhotos, activeCategory, searchQuery])

  return {
    filteredPhotos,
    categories,
    isLoading: library === null
  }
}
