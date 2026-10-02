/** Color theme: 'dark' (default) or 'light', persisted in localStorage. */
export type Theme = 'dark' | 'light'

const KEY = 'acr-theme'

export function getTheme(): Theme {
  try {
    return window.localStorage.getItem(KEY) === 'light' ? 'light' : 'dark'
  } catch {
    return 'dark'
  }
}

export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme
  try {
    window.localStorage.setItem(KEY, theme)
  } catch {
    /* private mode: theme applies for this session only */
  }
}

export function toggleTheme(): Theme {
  const next: Theme = getTheme() === 'dark' ? 'light' : 'dark'
  applyTheme(next)
  window.dispatchEvent(new CustomEvent('acr:theme-changed', { detail: next }))
  return next
}
