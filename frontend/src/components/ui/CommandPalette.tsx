import { AnimatePresence, motion } from 'framer-motion'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getTheme, toggleTheme } from '../../lib/theme'

interface Cmd {
  id: string
  label: string
  group: 'GO' | 'ACT'
  keywords?: string
  run: () => void
}

const ROUTES: Array<{ to: string; label: string; keywords?: string }> = [
  { to: '/overview', label: 'Overview', keywords: 'dashboard stats' },
  { to: '/investigate', label: 'Investigate', keywords: 'graph timeline chains' },
  { to: '/chains', label: 'Chains', keywords: 'reconstructed list' },
  { to: '/events', label: 'Events', keywords: 'telemetry raw' },
  { to: '/data', label: 'Data', keywords: 'datasets catalog ingest' },
  { to: '/attack', label: 'ATT&CK', keywords: 'mitre techniques coverage' },
  { to: '/simulate', label: 'Simulate', keywords: 'scenarios generate' },
  { to: '/evaluate', label: 'Evaluate', keywords: 'metrics stages precision recall' },
  { to: '/system', label: 'System', keywords: 'health pipeline config upload' },
]

export default function CommandPalette() {
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [index, setIndex] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)

  const commands = useMemo<Cmd[]>(() => {
    const nav: Cmd[] = ROUTES.map((r) => ({
      id: 'go:' + r.to,
      label: r.label,
      group: 'GO',
      keywords: r.keywords,
      run: () => {
        navigate(r.to)
        setOpen(false)
      },
    }))
    const act: Cmd[] = [
      {
        id: 'act:theme',
        label: `Switch to ${getTheme() === 'dark' ? 'light' : 'dark'} theme`,
        group: 'ACT',
        keywords: 'theme dark light appearance toggle',
        run: () => {
          toggleTheme()
          setOpen(false)
        },
      },
      {
        id: 'act:home',
        label: 'Landing page',
        group: 'ACT',
        keywords: 'home splash intro',
        run: () => {
          navigate('/')
          setOpen(false)
        },
      },
    ]
    return [...nav, ...act]
  }, [navigate])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return commands
    return commands.filter(
      (c) => c.label.toLowerCase().includes(q) || (c.keywords ?? '').toLowerCase().includes(q) || c.id.includes(q),
    )
  }, [commands, query])

  useEffect(() => {
    const openPalette = () => {
      setQuery('')
      setIndex(0)
      setOpen(true)
    }
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        if (open) {
          setOpen(false)
        } else {
          openPalette()
        }
        return
      }
      if (e.key === 'Escape') setOpen(false)
    }
    window.addEventListener('keydown', onKey)
    window.addEventListener('acr:open-palette', openPalette)
    return () => {
      window.removeEventListener('keydown', onKey)
      window.removeEventListener('acr:open-palette', openPalette)
    }
  }, [open])

  useEffect(() => {
    if (open) window.setTimeout(() => inputRef.current?.focus(), 30)
  }, [open])

  const choose = (i: number) => {
    const cmd = filtered[i]
    if (cmd) cmd.run()
  }

  const active = filtered.length > 0 ? Math.min(index, filtered.length - 1) : 0

  return (
    <AnimatePresence>
      {open ? (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.14 }}
          className="fixed inset-0 z-[70] flex items-start justify-center bg-base/75 pt-[14vh] backdrop-blur-sm"
          onClick={() => setOpen(false)}
          role="dialog"
          aria-modal="true"
          aria-label="Command palette"
        >
          <motion.div
            initial={{ y: -10, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: -10, opacity: 0 }}
            transition={{ duration: 0.16 }}
            className="w-[min(560px,calc(100vw-2rem))] overflow-hidden rounded-sm border border-line-strong bg-panel shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center gap-3 border-b border-line px-4 py-3">
              <span className="text-[12px] text-fg-faint mono">{'\u203A'}</span>
              <input
                ref={inputRef}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'ArrowDown') {
                    e.preventDefault()
                    setIndex((i) => Math.min(i + 1, filtered.length - 1))
                  } else if (e.key === 'ArrowUp') {
                    e.preventDefault()
                    setIndex((i) => Math.max(i - 1, 0))
                  } else if (e.key === 'Enter') {
                    e.preventDefault()
                    choose(active)
                  }
                }}
                placeholder="Type a command or page…"
                className="w-full bg-transparent text-[13px] text-fg placeholder:text-fg-faint focus:outline-none"
                aria-label="Command palette input"
              />
              <span className="shrink-0 rounded-sm border border-line px-1.5 py-0.5 text-[9px] tracking-[0.1em] text-fg-faint">
                ESC
              </span>
            </div>

            <ul className="max-h-[46vh] overflow-y-auto py-1.5">
              {filtered.length === 0 ? (
                <li className="px-4 py-6 text-center text-[11px] tracking-[0.14em] text-fg-faint">
                  NO MATCHING COMMANDS
                </li>
              ) : (
                filtered.map((c, i) => (
                  <li key={c.id}>
                    <button
                      onMouseEnter={() => setIndex(i)}
                      onClick={() => choose(i)}
                      className={`flex w-full items-center justify-between px-4 py-2 text-left transition-colors ${
                        i === active ? 'bg-white/6' : ''
                      }`}
                    >
                      <span className="flex items-center gap-3">
                        <span
                          className={`w-7 shrink-0 text-[9px] font-semibold tracking-[0.1em] ${
                            c.group === 'GO' ? 'text-fg-muted' : 'text-fg-faint'
                          }`}
                        >
                          {c.group}
                        </span>
                        <span className={`text-[12.5px] ${i === active ? 'text-fg' : 'text-fg-muted'}`}>{c.label}</span>
                      </span>
                      <span className="text-[9px] tracking-[0.1em] text-fg-faint">{c.id.startsWith('go:') ? c.id.slice(3) : ''}</span>
                    </button>
                  </li>
                ))
              )}
            </ul>

            <div className="flex items-center justify-between border-t border-line px-4 py-2 text-[9.5px] tracking-[0.1em] text-fg-faint">
              <span>{'\u2191\u2193'} NAVIGATE</span>
              <span>ENTER RUN</span>
              <span>CMD/CTRL+K TOGGLE</span>
            </div>
          </motion.div>
        </motion.div>
      ) : null}
    </AnimatePresence>
  )
}
