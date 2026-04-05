import { Routes, Route, NavLink } from 'react-router-dom'
import Library from './pages/Library.jsx'
import Posts from './pages/Posts.jsx'
import Post from './pages/Post.jsx'
import './App.css'

function App() {
  return (
    <div className="site">
      <header className="site-header">
        <h1><a href="#/">Brandon Stewart</a></h1>
        <nav className="site-nav">
          <NavLink to="/">Library</NavLink>
          <NavLink to="/posts">Posts</NavLink>
        </nav>
      </header>

      <main>
        <Routes>
          <Route path="/" element={<Library />} />
          <Route path="/library/*" element={<Library />} />
          <Route path="/posts" element={<Posts />} />
          <Route path="/posts/:slug" element={<Post />} />
        </Routes>
      </main>

      <footer className="site-footer">
        Brandon Stewart
      </footer>
    </div>
  )
}

export default App
