import { useEffect } from 'react'

function Lightbox({ photo, onClose }) {
  useEffect(() => {
    const handleKey = (e) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handleKey)
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', handleKey)
      document.body.style.overflow = ''
    }
  }, [onClose])

  const src = photo.src?.startsWith('http')
    ? photo.src
    : (typeof photo.src === 'string' && photo.src.startsWith(import.meta.env.BASE_URL)
      ? photo.src
      : import.meta.env.BASE_URL + photo.src)

  return (
    <div className="lightbox-overlay" onClick={onClose}>
      <img
        src={src}
        alt={photo.alt || photo.caption || ''}
        onClick={(e) => e.stopPropagation()}
      />
      {photo.caption && (
        <div className="lightbox-caption">{photo.caption}</div>
      )}
    </div>
  )
}

export default Lightbox
