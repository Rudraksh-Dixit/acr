import { AnimatePresence, motion } from 'framer-motion'
import { useCallback, useMemo, useRef, useState, type ReactNode } from 'react'
import { ToastContext, type ToastApi, type ToastItem, type ToastTone } from '../../lib/toast'

const TONE_STYLE: Record<ToastTone, { border: string; text: string; label: string }> = {
  ok: { border: 'var(--color-confirmed)', text: 'var(--color-confirmed)', label: 'OK' },
  error: { border: 'var(--color-risk)', text: 'var(--color-risk)', label: 'ERR' },
  info: { border: 'var(--color-warm)', text: 'var(--color-warm)', label: 'INF' },
}

const MAX_VISIBLE = 4
const DISMISS_MS = 4500

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([])
  const seq = useRef(0)

  const remove = useCallback((id: number) => {
    setItems((prev) => prev.filter((t) => t.id !== id))
  }, [])

  const push = useCallback(
    (tone: ToastTone, message: string) => {
      seq.current += 1
      const id = seq.current
      setItems((prev) => [...prev.slice(-(MAX_VISIBLE - 1)), { id, tone, message }])
      window.setTimeout(() => remove(id), DISMISS_MS)
    },
    [remove],
  )

  const api = useMemo<ToastApi>(
    () => ({
      success: (m) => push('ok', m),
      error: (m) => push('error', m),
      info: (m) => push('info', m),
    }),
    [push],
  )

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div
        className="pointer-events-none fixed right-4 bottom-4 z-[60] flex w-[min(420px,calc(100vw-2rem))] flex-col gap-2"
        role="status"
        aria-live="polite"
      >
        <AnimatePresence>
          {items.map((t) => {
            const style = TONE_STYLE[t.tone]
            return (
              <motion.button
                key={t.id}
                type="button"
                initial={{ opacity: 0, x: 24 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 24 }}
                transition={{ duration: 0.18 }}
                onClick={() => remove(t.id)}
                className="pointer-events-auto flex items-start gap-3 rounded-sm border bg-panel/95 px-3 py-2.5 text-left backdrop-blur-md"
                style={{ borderColor: style.border }}
              >
                <span className="mt-px shrink-0 text-[9px] font-semibold tracking-[0.14em]" style={{ color: style.text }}>
                  {style.label}
                </span>
                <span className="min-w-0 flex-1 text-[11px] leading-snug break-words text-fg-muted">{t.message}</span>
                <span className="shrink-0 text-[10px] text-fg-faint" aria-label="Dismiss">
                  ✕
                </span>
              </motion.button>
            )
          })}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  )
}
