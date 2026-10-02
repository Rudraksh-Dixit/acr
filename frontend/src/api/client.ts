/** Minimal typed fetch wrapper around the ACR REST API. */

const BASE: string = (import.meta.env.VITE_API_BASE as string | undefined) ?? ''

export class ApiError extends Error {
  readonly status: number
  readonly body: unknown

  constructor(status: number, message: string, body: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.body = body
  }
}

export function apiUrl(path: string, params?: Record<string, string | number | boolean | undefined | null>): string {
  const url = new URL(BASE + path, window.location.origin)
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null && value !== '') {
        url.searchParams.set(key, String(value))
      }
    }
  }
  return url.pathname + url.search
}

async function request<T>(path: string, init?: RequestInit, params?: Parameters<typeof apiUrl>[1]): Promise<T> {
  let response: Response
  try {
    response = await fetch(apiUrl(path, params), {
      headers: { Accept: 'application/json', ...(init?.body && !(init.body instanceof FormData) ? { 'Content-Type': 'application/json' } : {}), ...init?.headers },
      ...init,
    })
  } catch (cause) {
    throw new ApiError(0, 'ACR ENGINE OFFLINE — network request failed', cause)
  }

  const text = await response.text()
  let body: unknown = null
  if (text) {
    try {
      body = JSON.parse(text)
    } catch {
      body = text
    }
  }

  if (!response.ok) {
    const detail =
      typeof body === 'object' && body !== null && 'detail' in body
        ? JSON.stringify((body as { detail: unknown }).detail)
        : response.statusText
    throw new ApiError(response.status, `${response.status} ${detail}`, body)
  }
  return body as T
}

export const http = {
  get<T>(path: string, params?: Parameters<typeof apiUrl>[1]): Promise<T> {
    return request<T>(path, { method: 'GET' }, params)
  },
  post<T>(path: string, body?: unknown): Promise<T> {
    return request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) })
  },
  postForm<T>(path: string, form: FormData, params?: Parameters<typeof apiUrl>[1]): Promise<T> {
    return request<T>(path, { method: 'POST', body: form }, params)
  },
}
