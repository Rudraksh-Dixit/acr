import { AnimatePresence, motion } from 'framer-motion'
import { useEffect, useState } from 'react'
import { getHealth, getStats } from '../../api/system'
import { listChains } from '../../api/chains'
import { StatusDot } from '../ui/primitives'

type Stage = {
  label: string
  run: () => Promise<unknown>
}

const BOOT_KEY = 'acr:booted'

/** First-entry system sequence. Each stage awaits a real API call —
 *  no artificial delays beyond a short readability floor. */
export function BootSequence({ onDone }: { onDone?: () => void }) {
  const [index, setIndex] = useState(0)
  const [failed, setFailed] = useState<string | null>(null)

  const stages: Stage[] = [
    { label: 'CONNECTING TO ACR', run: () => getHealth() },
    { label: 'LOADING TELEMETRY', run: () => getStats() },
    { label: 'RECONSTRUCTING CHAINS', run: () => listChains({ limit: 5 }) },
    { label: 'READY', run: async () => undefined },
  ]

  useEffect(() => {
    let cancelled = false
    const start = performance.now()

    const step = async (i: number): Promise<void> => {
      if (cancelled || i >= stages.length) {
        if (!cancelled) {
          sessionStorage.setItem(BOOT_KEY, '1')
          onDone?.()
        }
        return
      }
      setIndex(i)
      const t0 = performance.now()
      try {
        await stages[i].run()
      } catch (error) {
        if (!cancelled) {
          setFailed(error instanceof Error ? error.message : String(error))
          sessionStorage.setItem(BOOT_KEY, '1')
          onDone?.()
        }
        return
      }
      // readability floor so the sequence reads as a sequence
      const elapsed = performance.now() - t0
      const floor = 260
      if (elapsed < floor) await new Promise((r) => setTimeout(r, floor - elapsed))
      if (!cancelled) await step(i + 1)
    }

    void step(0)
    void start
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <motion.div
      className="fixed inset-0 z-50 flex flex-col items-center justify-center gap-10 bg-base"
      exit={{ opacity: 0 }}
      transition={{ duration: 0.5, ease: 'easeInOut' }}
    >
      <div className="flex flex-col items-center gap-3">
        <span className="display text-2xl font-semibold tracking-[0.3em] text-fg">ACR</span>
        <span className="tech-label">Attack Chain Reconstruction Engine</span>
      </div>

      <ul className="flex w-72 flex-col gap-3">
        {stages.map((stage, i) => {
          const state = i < index ? 'done' : i === index ? 'active' : 'pending'
          return (
            <li key={stage.label} className="flex items-center gap-3">
              <span
                className="inline-block h-1.5 w-1.5 rounded-full transition-colors"
                style={{
                  background:
                    state === 'done'
                      ? 'var(--color-confirmed)'
                      : state === 'active'
                        ? 'var(--color-fg)'
                        : 'var(--color-line-strong)',
                }}
              />
              <span
                className={`text-[11px] tracking-[0.18em] transition-colors ${
                  state === 'pending' ? 'text-fg-faint/50' : 'text-fg-muted'
                }`}
              >
                {stage.label}
              </span>
              {state === 'active' ? (
                <motion.span
                  className="ml-auto h-px flex-1 origin-left bg-white/30"
                  initial={{ scaleX: 0 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.4 }}
                />
              ) : null}
            </li>
          )
        })}
      </ul>

      <AnimatePresence>
        {failed ? (
          <motion.div
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-center gap-2 rounded-sm border border-risk/40 bg-risk-deep/40 px-3 py-2"
          >
            <StatusDot tone="down" />
            <span className="text-[11px] tracking-[0.12em] text-risk">ACR ENGINE OFFLINE</span>
            <span className="text-[11px] text-fg-faint mono">{failed}</span>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </motion.div>
  )
}

export function hasBooted(): boolean {
  return sessionStorage.getItem(BOOT_KEY) === '1'
}
