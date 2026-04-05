import { useEffect, useRef } from 'react'

function Lightbox({ photo, onClose }) {
  const overlayRef = useRef(null)
  const previousFocus = useRef(null)

  useEffect(() => {
    previousFocus.current = document.activeElement
    overlayRef.current?.focus()

    const handleKey = (e) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handleKey)
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', handleKey)
      document.body.style.overflow = ''
      previousFocus.current?.focus()
    }
  }, [onClose])

  const src = photo.src?.startsWith('http')
    ? photo.src
    : (typeof photo.src === 'string' && photo.src.startsWith(import.meta.env.BASE_URL)
      ? photo.src
      : import.meta.env.BASE_URL + photo.src)

  const hasInfo = photo.caption || photo.species

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
    >
      <button
        className="lightbox-close"
        onClick={(e) => { e.stopPropagation(); onClose() }}
        aria-label="Close lightbox"
        type="button"
      >
        &times;
      </button>
      <img
        src={src}
        alt={photo.alt || photo.caption || ''}
      />
      {hasInfo && (
        <div className="lightbox-info" onClick={(e) => e.stopPropagation()}>
          {photo.caption && <div className="lightbox-title">{photo.caption}</div>}
          {photo.species && <div className="lightbox-species">{photo.species}</div>}
        </div>
      )}
    </div>
  )
}

export default Lightbox
