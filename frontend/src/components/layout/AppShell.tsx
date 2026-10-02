import { useEffect, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import TopNav from './TopNav'

/** app chrome: fixed nav + routed content, landing excluded */
export default function AppShell() {
  const { pathname } = useLocation()
  const [scrolled, setScrolled] = useState(false)

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 4)
    onScroll()
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  useEffect(() => {
    window.scrollTo(0, 0)
  }, [pathname])

  return (
    <div className="min-h-dvh">
      <TopNav />
      <main className="pt-12">
        <Outlet />
      </main>
      {scrolled ? null : null}
    </div>
  )
}
