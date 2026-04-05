import { useState, useEffect, useMemo } from 'react'
import { Link, useLocation } from 'react-router-dom'
import Lightbox from '../components/Lightbox.jsx'

function collectAllPhotos(node) {
  const photos = [...(node.photos || [])]
  for (const cat of node.categories || []) {
    photos.push(...collectAllPhotos(cat))
  }
  return photos
}

function Library() {
  const [library, setLibrary] = useState(null)
  const [lightboxPhoto, setLightboxPhoto] = useState(null)
  const location = useLocation()

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

  const randomBgPhoto = useMemo(() => {
    if (!library) return null
    const allPhotos = collectAllPhotos(library)
    if (allPhotos.length === 0) return null
    return allPhotos[Math.floor(Math.random() * allPhotos.length)]
  }, [library])

  if (!library) return null

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
  const isRoot = pathSegments.length === 0

  return (
    <div>
      {isRoot ? (
        <section className="intro-hero">
          {randomBgPhoto && (
            <div
              className="intro-bg"
              style={{
                backgroundImage: `url(${import.meta.env.BASE_URL + randomBgPhoto.src})`
              }}
            />
          )}
          <div className="intro-content">
            <h1 className="intro-heading">Hi, I'm Brandon<span className="intro-dot">.</span></h1>
            <p className="intro-subtitle">Software Engineer / Product Security Engineer</p>
            <p className="intro-description">
              Welcome to my photography blog. I shoot macro photography of arthropods
              and the small creatures most people walk right past — capturing the
              intricate details of the natural world up close.
            </p>
            <div className="intro-links">
              <a href="https://github.com/boveus" aria-label="GitHub" target="_blank" rel="noopener noreferrer">
                <svg viewBox="0 0 24 24" width="22" height="22" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
              </a>
              <a href="mailto:me@brandonsstewart.com" aria-label="Email">
                <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M22 4L12 13 2 4"/></svg>
              </a>
              <a href="https://www.linkedin.com/in/brandon-scott-stewart/" aria-label="LinkedIn" target="_blank" rel="noopener noreferrer">
                <svg viewBox="0 0 24 24" width="22" height="22" fill="currentColor"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 01-2.063-2.065 2.064 2.064 0 112.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/></svg>
              </a>
            </div>
          </div>
        </section>
      ) : (
        <>
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
        </>
      )}

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

      {photos.length > 0 && (
        <div className="photo-grid" style={{ marginTop: '24px' }}>
          {photos.map((photo) => (
            <button
              key={photo.src}
              className="photo-card"
              onClick={() => setLightboxPhoto(photo)}
              type="button"
            >
              <img
                src={import.meta.env.BASE_URL + photo.src}
                alt={photo.alt || ''}
                loading="lazy"
              />
              {(photo.caption || photo.species || photo.description || photo.location) && (
                <div className="photo-info">
                  {photo.caption && <span>{photo.caption}</span>}
                  {photo.species && <span className="photo-species">{photo.species}</span>}
                  {photo.description && <span className="photo-description">{photo.description}</span>}
                  {photo.location && <span className="photo-location">{photo.location}</span>}
                </div>
              )}
            </button>
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
