import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import Markdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import Lightbox from '../components/Lightbox.jsx'

function Post() {
  const { slug } = useParams()
  const [meta, setMeta] = useState(null)
  const [content, setContent] = useState('')
  const [lightboxPhoto, setLightboxPhoto] = useState(null)

  useEffect(() => {
    const controller = new AbortController()
    const { signal } = controller

    fetch(import.meta.env.BASE_URL + 'posts/index.json', { signal })
      .then(r => r.json())
      .then(data => {
        const post = data.posts.find(p => p.slug === slug)
        setMeta(post || null)
      })
      .catch(err => {
        if (!signal.aborted) setMeta(null)
      })

    fetch(import.meta.env.BASE_URL + `posts/${slug}.md`, { signal })
      .then(r => {
        if (!r.ok) throw new Error('Not found')
        return r.text()
      })
      .then(text => {
        const stripped = text.replace(/^---[\s\S]*?---\n*/, '')
        setContent(stripped)
      })
      .catch(err => {
        if (!signal.aborted) setContent('Post not found.')
      })

    return () => controller.abort()
  }, [slug])

  if (meta === null && content === '') return null

  return (
    <div>
      <Link to="/posts" className="back-link">&larr; All posts</Link>

      <div className="post-header">
        <h1 className="page-title">{meta?.title || slug}</h1>
        {meta?.date && (
          <div className="post-date">{formatDate(meta.date)}</div>
        )}
      </div>

      <div className="post-content">
        <Markdown
          remarkPlugins={[remarkGfm]}
          components={{
            img: ({ src, alt, ...props }) => {
              const resolvedSrc = src?.startsWith('http')
                ? src
                : import.meta.env.BASE_URL + src
              return (
                <figure className="post-photo">
                  <button
                    type="button"
                    className="post-photo-button"
                    onClick={() =>
                      setLightboxPhoto({ src: resolvedSrc, caption: alt })
                    }
                  >
                    <img
                      {...props}
                      src={resolvedSrc}
                      alt={alt || ''}
                      loading="lazy"
                    />
                  </button>
                  {alt && <figcaption>{alt}</figcaption>}
                </figure>
              )
            },
          }}
        >
          {content}
        </Markdown>
      </div>

      {lightboxPhoto && (
        <Lightbox
          photo={lightboxPhoto}
          onClose={() => setLightboxPhoto(null)}
        />
      )}
    </div>
  )
}

function formatDate(dateStr) {
  return new Date(dateStr + 'T00:00:00').toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  })
}

export default Post
