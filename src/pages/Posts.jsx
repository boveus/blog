import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'

function Posts() {
  const [posts, setPosts] = useState(null)

  useEffect(() => {
    fetch(import.meta.env.BASE_URL + 'posts/index.json')
      .then(r => r.json())
      .then(data => {
        // Sort by date descending
        const sorted = data.posts.sort(
          (a, b) => new Date(b.date) - new Date(a.date)
        )
        setPosts(sorted)
      })
      .catch(() => setPosts([]))
  }, [])

  if (!posts) return null

  return (
    <div>
      <h1 className="page-title">Posts</h1>
      <p className="page-subtitle">Stories behind the photos</p>

      <div className="post-list">
        {posts.map(post => (
          <div key={post.slug} className="post-preview">
            <h2>
              <Link to={`/posts/${post.slug}`}>{post.title}</Link>
            </h2>
            <div className="post-date">{formatDate(post.date)}</div>
            {post.excerpt && <p className="post-excerpt">{post.excerpt}</p>}
          </div>
        ))}

        {posts.length === 0 && (
          <p style={{ color: 'var(--text-light)' }}>No posts yet.</p>
        )}
      </div>
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

export default Posts
