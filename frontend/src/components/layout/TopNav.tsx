import { useState } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { useHealth, useStats } from '../../hooks/queries'
import { getTheme, toggleTheme, type Theme } from '../../lib/theme'
import { StatusDot, TechLabel } from '../ui/primitives'

const NAV = [
  { to: '/overview', label: 'OVERVIEW' },
  { to: '/investigate', label: 'INVESTIGATE' },
  { to: '/chains', label: 'CHAINS' },
  { to: '/events', label: 'EVENTS' },
  { to: '/data', label: 'DATA' },
  { to: '/attack', label: 'ATT&CK' },
  { to: '/simulate', label: 'SIMULATE' },
]

export default function TopNav() {
  const health = useHealth()
  const stats = useStats()
  const location = useLocation()
  const [theme, setThemeState] = useState<Theme>(() => getTheme())

  const online = health.data?.status === 'ok'
  const down = health.isError
  const eventCount = stats.data?.counts.events

  return (
    <header className="fixed inset-x-0 top-0 z-40 border-b border-line bg-base/88 backdrop-blur-md">
      <div className="mx-auto flex h-12 max-[1920px]:px-5 items-center gap-6 px-8">
        <NavLink to="/investigate" className="flex items-baseline gap-2.5" aria-label="ACR home">
          <span className="display text-[15px] font-semibold tracking-[0.2em] text-fg">ACR</span>
          <TechLabel className="hidden lg:inline">Attack Chain Reconstruction</TechLabel>
        </NavLink>

        <nav className="ml-4 flex items-center gap-1" aria-label="Primary">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `relative rounded-sm px-2.5 py-1.5 text-[11px] font-medium tracking-[0.14em] transition-colors ${
                  isActive ? 'text-fg' : 'text-fg-faint hover:text-fg-muted'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  {item.label}
                  {isActive ? (
                    <span className="absolute inset-x-2.5 -bottom-px h-px bg-fg" style={{ background: 'var(--color-fg)' }} />
                  ) : null}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        <div className="ml-auto flex items-center gap-4">
          <NavLink
            to="/evaluate"
            className={`text-[11px] tracking-[0.14em] transition-colors ${
              location.pathname === '/evaluate' ? 'text-fg' : 'text-fg-faint hover:text-fg-muted'
            }`}
          >
            EVALUATE
          </NavLink>

          <button
            onClick={() => setThemeState(toggleTheme())}
            className="rounded-sm border border-line px-2 py-1 text-[10px] font-medium tracking-[0.14em] text-fg-muted transition-colors hover:border-line-strong"
            title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
            aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
          >
            {theme === 'dark' ? 'LIGHT' : 'DARK'}
          </button>

          {eventCount != null ? (
            <span className="hidden items-center gap-2 md:flex">
              <TechLabel>{eventCount} EVENTS</TechLabel>
            </span>
          ) : null}

          <NavLink
            to="/system"
            className="flex items-center gap-2 rounded-sm border border-line px-2.5 py-1 transition-colors hover:border-line-strong"
            title="System status"
          >
            <StatusDot tone={online ? 'ok' : down ? 'down' : 'warn'} pulse={down} />
            <span className="text-[10px] font-medium tracking-[0.14em] text-fg-muted">
              {online ? 'API ONLINE' : down ? 'API OFFLINE' : 'CONNECTING'}
            </span>
          </NavLink>
        </div>
      </div>
    </header>
  )
}
