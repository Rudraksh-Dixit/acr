import gsap from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import { useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { useConfig, useHealth, useStats } from '../hooks/systemQueries'

gsap.registerPlugin(ScrollTrigger)

/** Decorative particle field: scattered chaos converges into an attack chain
 *  as the intro scrolls. Purely visual — all numeric claims come from the API. */
function ChaosCanvas({ progressRef }: { progressRef: React.RefObject<number> }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    let raf = 0
    let w = 0
    let h = 0
    const dpr = Math.min(2, window.devicePixelRatio || 1)

    const resize = () => {
      w = canvas.clientWidth
      h = canvas.clientHeight
      canvas.width = Math.max(1, w * dpr)
      canvas.height = Math.max(1, h * dpr)
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    }
    resize()
    window.addEventListener('resize', resize)

    const COUNT = 150
    const seeds = Array.from({ length: COUNT }, (_, i) => ({
      chaos: { x: Math.random(), y: Math.random(), vx: (Math.random() - 0.5) * 0.0006, vy: (Math.random() - 0.5) * 0.0006 },
      // target: spine node along the bottom third, entities branching above/below
      t: i / (COUNT - 1),
      lane: (i % 7) - 3,
      wob: Math.random() * Math.PI * 2,
      hue: Math.random() < 0.18 ? 42 : Math.random() < 0.12 ? 262 : 0,
    }))

    const draw = () => {
      const p = Math.max(0, Math.min(1, progressRef.current ?? 0))
      const ease = p * p * (3 - 2 * p) // smoothstep
      ctx.clearRect(0, 0, w, h)

      const pts: Array<{ x: number; y: number; hue: number }> = []
      const marginX = w * 0.08
      const spineY = h * 0.62

      for (const s of seeds) {
        s.chaos.x += s.chaos.vx
        s.chaos.y += s.chaos.vy
        if (s.chaos.x < 0 || s.chaos.x > 1) s.chaos.vx *= -1
        if (s.chaos.y < 0 || s.chaos.y > 1) s.chaos.vy *= -1

        const chaosX = s.chaos.x * w
        const chaosY = s.chaos.y * h

        const chainX = marginX + s.t * (w - marginX * 2)
        const isSpine = s.lane === 0
        const chainY = isSpine ? spineY : spineY + s.lane * (h * 0.055)

        const x = chaosX + (chainX - chaosX) * ease
        const y = chaosY + (chainY - chaosY) * ease + Math.sin(s.wob + performance.now() * 0.001) * (1 - ease) * 6
        pts.push({ x, y, hue: s.hue })
      }

      // chaos web: faint spurious links while scattered
      const chaosAlpha = (1 - ease) * 0.16
      if (chaosAlpha > 0.01) {
        ctx.lineWidth = 0.6
        for (let i = 0; i < pts.length; i += 7) {
          for (let j = i + 3; j < Math.min(i + 12, pts.length); j += 4) {
            const a = pts[i]
            const b = pts[j]
            const d = Math.hypot(a.x - b.x, a.y - b.y)
            if (d > 260) continue
            ctx.strokeStyle = `rgba(255,255,255,${chaosAlpha * (1 - d / 260)})`
            ctx.beginPath()
            ctx.moveTo(a.x, a.y)
            ctx.lineTo(b.x, b.y)
            ctx.stroke()
          }
        }
      }

      // chain spine: ordered links appear with progress
      const spine = pts.filter((_, i) => seeds[i].lane === 0).sort((a, b) => a.x - b.x)
      const linkAlpha = Math.max(0, ease * 2 - 0.6)
      if (linkAlpha > 0.01) {
        ctx.lineWidth = 1.2
        ctx.strokeStyle = `rgba(255,255,255,${0.55 * linkAlpha})`
        ctx.beginPath()
        spine.forEach((pt, i) => (i === 0 ? ctx.moveTo(pt.x, pt.y) : ctx.lineTo(pt.x, pt.y)))
        ctx.stroke()

        // entity branches
        ctx.lineWidth = 0.8
        ctx.strokeStyle = `rgba(255,255,255,${0.2 * linkAlpha})`
        for (let i = 1; i < spine.length; i += 3) {
          const branch = pts.filter((_, j) => seeds[j].lane !== 0)[i % 6]
          if (!branch) continue
          ctx.beginPath()
          ctx.moveTo(spine[i].x, spine[i].y)
          ctx.lineTo(branch.x, branch.y)
          ctx.stroke()
        }
      }

      // particles
      for (let i = 0; i < pts.length; i++) {
        const pt = pts[i]
        const isSpineNode = seeds[i].lane === 0
        const r = isSpineNode ? 2.6 : 1.8
        const color =
          pt.hue === 42
            ? `rgba(217,164,65,${0.35 + ease * 0.5})`
            : pt.hue === 262
              ? `rgba(157,140,255,${0.3 + ease * 0.55})`
              : `rgba(255,255,255,${0.25 + ease * (isSpineNode ? 0.65 : 0.35)})`
        ctx.fillStyle = color
        ctx.beginPath()
        ctx.arc(pt.x, pt.y, r + ease * (isSpineNode ? 0.8 : 0), 0, Math.PI * 2)
        ctx.fill()
      }

      raf = requestAnimationFrame(draw)
    }
    raf = requestAnimationFrame(draw)

    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('resize', resize)
    }
  }, [progressRef])

  return <canvas ref={canvasRef} className="absolute inset-0 h-full w-full" aria-hidden />
}

function Count({ value, label }: { value: number | string; label: string }) {
  return (
    <div>
      <div className="display text-4xl leading-none md:text-5xl">{value}</div>
      <div className="mt-2 text-[10px] tracking-[0.22em] text-fg-faint uppercase">{label}</div>
    </div>
  )
}

export default function Landing() {
  const navigate = useNavigate()
  const progressRef = useRef(0)
  const rootRef = useRef<HTMLDivElement>(null)

  const health = useHealth()
  const stats = useStats()
  const config = useConfig()

  useEffect(() => {
    const ctx = gsap.context(() => {
      gsap.from('.hero-line', {
        yPercent: 120,
        opacity: 0,
        duration: 1.1,
        ease: 'power3.out',
        stagger: 0.12,
        delay: 0.15,
      })
      gsap.from('.hero-sub', { opacity: 0, y: 14, duration: 0.9, ease: 'power2.out', delay: 0.8 })
      gsap.from('.hero-cta', { opacity: 0, y: 14, duration: 0.9, ease: 'power2.out', delay: 1.0 })

      ScrollTrigger.create({
        trigger: rootRef.current,
        start: 'top top',
        end: '+=160%',
        scrub: 0.6,
        onUpdate: (self) => {
          progressRef.current = self.progress
        },
      })

      gsap.utils.toArray<HTMLElement>('.reveal').forEach((el) => {
        gsap.from(el, {
          opacity: 0,
          y: 26,
          duration: 0.8,
          ease: 'power2.out',
          scrollTrigger: { trigger: el, start: 'top 85%' },
        })
      })
    }, rootRef)
    return () => ctx.revert()
  }, [])

  const weights = Object.entries(config.data?.weights ?? {}).sort((a, b) => b[1] - a[1])

  return (
    <div ref={rootRef} className="relative">
      {/* hero: sticky viewport, canvas driven by scroll progress */}
      <section className="relative h-[260vh]">
        <div className="sticky top-0 h-dvh overflow-hidden">
          <ChaosCanvas progressRef={progressRef} />
          <div className="absolute inset-0 bg-gradient-to-b from-base/70 via-transparent to-base/85" />

          {/* top bar */}
          <div className="absolute inset-x-0 top-0 flex items-center justify-between px-6 py-5 md:px-10">
            <span className="display text-sm tracking-[0.3em]">ACR</span>
            <button
              onClick={() => navigate('/investigate')}
              className="text-[10.5px] tracking-[0.2em] text-fg-muted transition-colors hover:text-fg uppercase"
            >
              Enter investigation {'\u2192'}
            </button>
          </div>

          {/* hero copy */}
          <div className="absolute inset-x-0 bottom-0 px-6 pb-14 md:px-10 md:pb-20">
            <div className="overflow-hidden">
              <h1 className="hero-line display text-[13vw] leading-[0.92] tracking-tight md:text-[7.5vw]">
                ATTACK CHAIN
              </h1>
            </div>
            <div className="overflow-hidden">
              <h1 className="hero-line display text-[13vw] leading-[0.92] tracking-tight md:text-[7.5vw]">
                RECONSTRUCTION
              </h1>
            </div>
            <p className="hero-sub mt-5 max-w-2xl text-[13.5px] leading-relaxed text-fg-muted md:text-[15px]">
              Correlate raw telemetry into temporal, causal attack chains — event by event, with every missing step
              marked as inferred, every confidence number derived from real signals, and detection seeds required
              before any chain is claimed.
            </p>
            <div className="hero-cta mt-7 flex flex-wrap items-center gap-4">
              <button
                onClick={() => navigate('/investigate')}
                className="rounded-sm border border-fg/70 px-7 py-3 text-[11.5px] tracking-[0.2em] transition-colors hover:bg-white/10 uppercase"
              >
                Investigate now
              </button>
              <button
                onClick={() => navigate('/evaluate')}
                className="text-[11.5px] tracking-[0.2em] text-fg-muted transition-colors hover:text-fg uppercase"
              >
                See the numbers
              </button>
              <span className="flex items-center gap-2 text-[10.5px] tracking-[0.14em] text-fg-faint uppercase">
                <span
                  className="inline-block h-1.5 w-1.5 rounded-full"
                  style={{
                    background:
                      health.data?.status === 'ok' ? 'var(--color-confirmed)' : 'var(--color-risk)',
                  }}
                />
                {health.data ? `engine ${health.data.version} online` : 'engine…'}
              </span>
            </div>
            <div className="mt-8 text-[10px] tracking-[0.24em] text-fg-faint uppercase">
              scroll — noise resolves into chain {'\u2193'}
            </div>
          </div>
        </div>
      </section>

      {/* real numbers strip */}
      <section className="border-t border-line bg-panel/40 px-6 py-16 md:px-10">
        <div className="mx-auto grid max-w-6xl grid-cols-2 gap-8 md:grid-cols-4">
          <div className="reveal">
            <Count value={stats.data?.counts.events ?? '\u2014'} label="events stored" />
          </div>
          <div className="reveal">
            <Count value={stats.data?.counts.chains ?? '\u2014'} label="chains reconstructed" />
          </div>
          <div className="reveal">
            <Count value={stats.data?.counts.detections ?? '\u2014'} label="detections seeded" />
          </div>
          <div className="reveal">
            <Count value={stats.data?.counts.techniques ?? '\u2014'} label="techniques mapped" />
          </div>
        </div>
        <p className="reveal mx-auto mt-10 max-w-2xl text-center text-[12.5px] leading-relaxed text-fg-faint">
          Figures are read live from <span className="text-fg-muted mono">/api/stats</span> — same numbers the
          engine reports to analysts, no mocked counters.
        </p>
      </section>

      {/* three-stage engine */}
      <section className="border-t border-line px-6 py-20 md:px-10">
        <div className="mx-auto max-w-6xl">
          <div className="reveal text-[10px] tracking-[0.24em] text-fg-faint uppercase">The engine</div>
          <h2 className="reveal display mt-3 text-4xl tracking-tight md:text-6xl">
            Detection first. Correlation second. Reconstruction last.
          </h2>
          <div className="mt-12 grid gap-6 md:grid-cols-3">
            {[
              {
                n: '01',
                t: 'RAW',
                d: 'Telemetry is normalized and detections fire. Benign activity never seeds a chain — zero false attack chains by construction.',
              },
              {
                n: '02',
                t: 'CORRELATION',
                d: `Weighted signals — temporal proximity, shared host and user, process lineage, network edges, attack progression — must cross a minimum edge score of ${config.data?.min_edge_score ?? '\u2014'}.`,
              },
              {
                n: '03',
                t: 'RECONSTRUCTION',
                d: 'Chains are assembled around detection seeds, scored for confidence and risk, and any technique gap is exposed as an explicitly inferred step.',
              },
            ].map((s) => (
              <div key={s.n} className="reveal border-t border-line-strong pt-5">
                <div className="flex items-baseline gap-3">
                  <span className="text-[11px] text-fg-faint mono">{s.n}</span>
                  <span className="text-[13px] tracking-[0.2em] text-fg uppercase">{s.t}</span>
                </div>
                <p className="mt-4 text-[13px] leading-relaxed text-fg-muted">{s.d}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* real correlation weights */}
      <section className="border-t border-line bg-panel/40 px-6 py-20 md:px-10">
        <div className="mx-auto max-w-4xl">
          <div className="reveal text-[10px] tracking-[0.24em] text-fg-faint uppercase">
            Live configuration — /api/config
          </div>
          <h2 className="reveal display mt-3 text-3xl tracking-tight md:text-5xl">
            Correlation weights, summing to exactly 100.
          </h2>
          <ul className="reveal mt-8 space-y-3">
            {weights.length === 0
              ? Array.from({ length: 5 }).map((_, i) => (
                  <li key={i} className="h-5 animate-pulse rounded-sm bg-white/5" />
                ))
              : weights.map(([name, w]) => (
                  <li key={name} className="grid grid-cols-[190px_1fr_36px] items-center gap-4">
                    <span className="truncate text-[12px] text-fg-muted mono">{name}</span>
                    <span className="h-2 overflow-hidden rounded-full bg-white/6">
                      <span className="block h-full rounded-full bg-white/55" style={{ width: `${w}%` }} />
                    </span>
                    <span className="text-right text-[12px] text-fg mono">{w}</span>
                  </li>
                ))}
          </ul>
          <p className="reveal mt-8 text-[12.5px] leading-relaxed text-fg-faint">
            Time alone never links events: same-host plus close timestamps still needs independent signals to cross
            the edge threshold.
          </p>
        </div>
      </section>

      {/* final CTA */}
      <section className="border-t border-line px-6 py-24 md:px-10">
        <div className="mx-auto max-w-4xl text-center">
          <h2 className="reveal display text-4xl tracking-tight md:text-6xl">Open the workspace.</h2>
          <p className="reveal mx-auto mt-5 max-w-xl text-[13.5px] leading-relaxed text-fg-muted">
            Graph, timeline, process lineage, network flows, MITRE coverage and evaluation metrics — one investigation
            surface over a working backend.
          </p>
          <div className="reveal mt-8 flex flex-wrap justify-center gap-4">
            <button
              onClick={() => navigate('/investigate')}
              className="rounded-sm border border-fg/70 px-7 py-3 text-[11.5px] tracking-[0.2em] hover:bg-white/10 uppercase"
            >
              Start investigating
            </button>
            <button
              onClick={() => navigate('/simulate')}
              className="rounded-sm border border-line-strong px-7 py-3 text-[11.5px] tracking-[0.2em] text-fg-muted hover:bg-white/6 uppercase"
            >
              Generate a scenario
            </button>
          </div>
        </div>
      </section>

      <footer className="border-t border-line px-6 py-6 text-[10.5px] tracking-[0.14em] text-fg-faint uppercase md:px-10">
        ACR — Attack Chain Reconstruction Engine {config.data?.version ? `· v${config.data.version}` : ''}
      </footer>
    </div>
  )
}
