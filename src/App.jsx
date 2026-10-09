import { Routes, Route, Link, Navigate } from 'react-router-dom'
import Library from './pages/Library.jsx'
import './App.css'

function App() {
  return (
    <div className="site">
      <button className="skip-link" onClick={() => document.getElementById("main-content").focus()}>Skip to content</button>
      <header className="site-header">
        <h1><Link to="/">Brandon Stewart</Link></h1>
      </header>

      <main id="main-content" tabIndex={-1}>
        <Routes>
          <Route path="/" element={<Library />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>

      <footer className="site-footer">
        <span>Brandon Stewart</span><span>Photography</span>
      </footer>
    </div>
  )
}

export default App
