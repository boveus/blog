import { useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import Lightbox from '../components/Lightbox.jsx'

function Library() {
  const [library, setLibrary] = useState(null)
  const [lightboxPhoto, setLightboxPhoto] = useState(null)
  const location = useLocation()

  // Parse current path from location
  // e.g. /library/macro/insects -> ["macro", "insects"]
  const pathSegments = location.pathname
    .replace(/^\/library\/?/, '')
    .split('/')
    .filter(Boolean)

  useEffect(() => {
    fetch(import.meta.env.BASE_URL + 'library.json')
      .then(r => r.json())
      .then(setLibrary)
      .catch(() => setLibrary({ categories: [], photos: [] }))
  }, [])

  if (!library) return null

  // Navigate into the tree based on path segments
  let currentNode = library
  for (const segment of pathSegments) {
    const child = (currentNode.categories || []).find(
      c => c.slug === segment
    )
    if (child) {
      currentNode = child
    } else {
      break
    }
  }

  const subcategories = currentNode.categories || []
  const photos = currentNode.photos || []
  const currentName = pathSegments.length > 0
    ? pathSegments[pathSegments.length - 1].replace(/-/g, ' ')
    : 'Library'

  return (
    <div>
      {/* Breadcrumb */}
      <nav className="breadcrumb">
        <Link to="/">Library</Link>
        {pathSegments.map((seg, i) => {
          const path = '/library/' + pathSegments.slice(0, i + 1).join('/')
          const isLast = i === pathSegments.length - 1
          return (
            <span key={path}>
              <span>/</span>{' '}
              {isLast ? (
                <span style={{ color: 'var(--text-heading)' }}>
                  {seg.replace(/-/g, ' ')}
                </span>
              ) : (
                <Link to={path}>{seg.replace(/-/g, ' ')}</Link>
              )}
            </span>
          )
        })}
      </nav>

      <h1 className="page-title" style={{ textTransform: 'capitalize' }}>
        {currentName}
      </h1>
      {pathSegments.length === 0 && (
        <p className="page-subtitle">Browse photos by category</p>
      )}

      {/* Subcategories */}
      {subcategories.length > 0 && (
        <div className="category-grid" style={{ marginTop: '24px' }}>
          {subcategories.map(cat => {
            const path = pathSegments.length > 0
              ? '/library/' + pathSegments.join('/') + '/' + cat.slug
              : '/library/' + cat.slug
            const photoCount = countPhotos(cat)
            return (
              <Link to={path} key={cat.slug} className="category-card">
                <span style={{ textTransform: 'capitalize' }}>
                  {cat.name}
                </span>
                <span className="count">
                  {photoCount} {photoCount === 1 ? 'photo' : 'photos'}
                </span>
              </Link>
            )
          })}
        </div>
      )}

      {/* Photos */}
      {photos.length > 0 && (
        <div className="photo-grid" style={{ marginTop: '24px' }}>
          {photos.map((photo, i) => (
            <div
              key={i}
              className="photo-card"
              onClick={() => setLightboxPhoto(photo)}
            >
              <img
                src={import.meta.env.BASE_URL + photo.src}
                alt={photo.alt || ''}
                loading="lazy"
              />
              {photo.caption && (
                <div className="photo-info">{photo.caption}</div>
              )}
            </div>
          ))}
        </div>
      )}

      {subcategories.length === 0 && photos.length === 0 && (
        <p style={{ color: 'var(--text-light)', marginTop: '24px' }}>
          No photos in this category yet.
        </p>
      )}

      {lightboxPhoto && (
        <Lightbox
          photo={lightboxPhoto}
          onClose={() => setLightboxPhoto(null)}
        />
      )}
    </div>
  )
}

function countPhotos(category) {
  let count = (category.photos || []).length
  for (const sub of category.categories || []) {
    count += countPhotos(sub)
  }
  return count
}

export default Library
