function FilterBar({ categories, activeCategory, onCategoryChange, searchQuery, onSearchChange, resultCount }) {
  return (
    <div className="filter-bar">
      <div className="filter-search">
        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="11" cy="11" r="8" />
          <line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
        <input
          type="text"
          placeholder="Search by species, caption, location..."
          value={searchQuery}
          onChange={e => onSearchChange(e.target.value)}
          className="filter-search-input"
          aria-label="Search photos"
        />
        {searchQuery && (
          <button
            className="filter-search-clear"
            onClick={() => onSearchChange('')}
            aria-label="Clear search"
            type="button"
          >
            &times;
          </button>
        )}
      </div>
      <div className="filter-chips" role="group" aria-label="Filter by category">
        {categories.map(cat => (
          <button
            key={cat}
            className={`filter-chip${activeCategory === cat ? ' filter-chip-active' : ''}`}
            onClick={() => onCategoryChange(cat)}
            aria-pressed={activeCategory === cat}
            type="button"
          >
            {cat}
          </button>
        ))}
      </div>
      <div className="filter-count" aria-live="polite">
        {resultCount} {resultCount === 1 ? 'photo' : 'photos'}
      </div>
    </div>
  )
}

export default FilterBar
