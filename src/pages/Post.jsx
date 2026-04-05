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
    // Load post metadata
    fetch(import.meta.env.BASE_URL + 'posts/index.json')
      .then(r => r.json())
      .then(data => {
        const post = data.posts.find(p => p.slug === slug)
        setMeta(post || null)
      })
      .catch(() => setMeta(null))

    // Load markdown content
    fetch(import.meta.env.BASE_URL + `posts/${slug}.md`)
      .then(r => {
        if (!r.ok) throw new Error('Not found')
        return r.text()
      })
      .then(text => {
        // Strip frontmatter if present
        const stripped = text.replace(/^---[\s\S]*?---\n*/, '')
        setContent(stripped)
      })
      .catch(() => setContent('Post not found.'))
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
              // Resolve relative image paths to the photos dir
              const resolvedSrc = src?.startsWith('http')
                ? src
                : import.meta.env.BASE_URL + src
              return (
                <figure className="post-photo">
                  <img
                    {...props}
                    src={resolvedSrc}
                    alt={alt || ''}
                    loading="lazy"
                    style={{ cursor: 'pointer' }}
                    onClick={() =>
                      setLightboxPhoto({ src: resolvedSrc, caption: alt })
                    }
                  />
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
