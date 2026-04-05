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
      <img
        src={src}
        alt={photo.alt || photo.caption || ''}
      />
      {photo.caption && (
        <div className="lightbox-caption" onClick={(e) => e.stopPropagation()}>
          {photo.caption}
        </div>
      )}
    </div>
  )
}

export default Lightbox
