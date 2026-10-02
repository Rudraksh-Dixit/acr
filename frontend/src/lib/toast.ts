import { createContext, useContext } from 'react'

export type ToastTone = 'ok' | 'error' | 'info'

export interface ToastItem {
  id: number
  tone: ToastTone
  message: string
}

export interface ToastApi {
  success: (message: string) => void
  error: (message: string) => void
  info: (message: string) => void
}

export const ToastContext = createContext<ToastApi | null>(null)

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext)
  if (!ctx) {
    return { success: () => {}, error: () => {}, info: () => {} }
  }
  return ctx
}
