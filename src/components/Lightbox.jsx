import { useEffect, useRef, useCallback } from 'react'

function Lightbox({ photos, currentIndex, onClose, onNext, onPrev }) {
  const overlayRef = useRef(null)
  const previousFocus = useRef(null)
  const touchStart = useRef(null)

  const photo = photos[currentIndex]

  const handleKey = useCallback((e) => {
    if (e.key === 'Escape') onClose()
    else if (e.key === 'ArrowRight') onNext()
    else if (e.key === 'ArrowLeft') onPrev()
  }, [onClose, onNext, onPrev])

  useEffect(() => {
    previousFocus.current = document.activeElement
    overlayRef.current?.focus()

    document.addEventListener('keydown', handleKey)
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', handleKey)
      document.body.style.overflow = ''
      previousFocus.current?.focus()
    }
  }, [handleKey])

  const handleTouchStart = useCallback((e) => {
    touchStart.current = e.touches[0].clientX
  }, [])

  const handleTouchEnd = useCallback((e) => {
    if (touchStart.current === null) return
    const delta = e.changedTouches[0].clientX - touchStart.current
    if (Math.abs(delta) > 50) {
      if (delta < 0) onNext()
      else onPrev()
    }
    touchStart.current = null
  }, [onNext, onPrev])

  const src = photo.src?.startsWith('http')
    ? photo.src
    : (typeof photo.src === 'string' && photo.src.startsWith(import.meta.env.BASE_URL)
      ? photo.src
      : import.meta.env.BASE_URL + photo.src)

  const hasInfo = photo.caption || photo.species || photo.description || photo.location

  return (
    <div
      ref={overlayRef}
      className="lightbox-overlay"
      role="dialog"
      aria-modal="true"
      aria-label={photo.caption || photo.alt || 'Photo lightbox'}
      tabIndex={-1}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
      onTouchStart={handleTouchStart}
      onTouchEnd={handleTouchEnd}
    >
      <button
        className="lightbox-close"
        onClick={(e) => { e.stopPropagation(); onClose() }}
        aria-label="Close lightbox"
        type="button"
      >
        &times;
      </button>

      {photos.length > 1 && (
        <div className="lightbox-counter">
          {currentIndex + 1} / {photos.length}
        </div>
      )}

      {photos.length > 1 && (
        <>
          <button
            className="lightbox-nav lightbox-prev"
            onClick={(e) => { e.stopPropagation(); onPrev() }}
            aria-label="Previous photo"
            type="button"
          >
            <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="15 18 9 12 15 6" /></svg>
          </button>
          <button
            className="lightbox-nav lightbox-next"
            onClick={(e) => { e.stopPropagation(); onNext() }}
            aria-label="Next photo"
            type="button"
          >
            <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="9 6 15 12 9 18" /></svg>
          </button>
        </>
      )}

      <img
        key={photo.src}
        src={src}
        alt={photo.alt || photo.caption || ''}
      />

      {hasInfo && (
        <div className="lightbox-info" onClick={(e) => e.stopPropagation()}>
          {photo.caption && <div className="lightbox-title">{photo.caption}</div>}
          {photo.species && <div className="lightbox-species">{photo.species}</div>}
          {photo.description && <div className="lightbox-description">{photo.description}</div>}
          {photo.location && <div className="lightbox-location">{photo.location}</div>}
        </div>
      )}
    </div>
  )
}

export default Lightbox
