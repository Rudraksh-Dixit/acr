import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AnimatePresence } from 'framer-motion'
import { useState } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import AppShell from '../components/layout/AppShell'
import { BootSequence, hasBooted } from '../components/layout/BootSequence'
import Attack from '../pages/Attack'
import Chains from '../pages/Chains'
import Evaluate from '../pages/Evaluate'
import Events from '../pages/Events'
import Investigate from '../pages/Investigate'
import Landing from '../pages/Landing'
import Simulate from '../pages/Simulate'
import SystemPage from '../pages/System'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 5_000,
    },
  },
})

export default function App() {
  const [booting, setBooting] = useState(() => !hasBooted())

  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AnimatePresence>
          {booting ? <BootSequence onDone={() => setBooting(false)} /> : null}
        </AnimatePresence>

        <Routes>
          <Route path="/" element={<Landing />} />
          <Route element={<AppShell />}>
            <Route path="/investigate" element={<Investigate />} />
            <Route path="/investigate/:chainId" element={<Investigate />} />
            <Route path="/chains" element={<Chains />} />
            <Route path="/events" element={<Events />} />
            <Route path="/attack" element={<Attack />} />
            <Route path="/simulate" element={<Simulate />} />
            <Route path="/evaluate" element={<Evaluate />} />
            <Route path="/system" element={<SystemPage />} />
            <Route path="*" element={<Navigate to="/investigate" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
