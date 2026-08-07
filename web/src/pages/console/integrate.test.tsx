import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import type { ReactNode } from 'react'
import { IntegratePage } from './integrate'

vi.mock('../../api', () => ({
  apiFetch: vi.fn(() => new Promise(() => {})),
}))

vi.mock('../../components/shells', () => ({
  ConsoleLayout: ({ children }: { children: ReactNode }) => <>{children}</>,
}))

vi.mock('./shared', () => ({
  entitlementState: () => ({
    kind: 'ready',
    plan: { code: 'basic', name: '基础版', description: null, validity: 'permanent' },
    data: { plan: { code: 'basic', name: '基础版', description: null, validity: 'permanent' }, entitlements: [] },
  }),
  SelfServiceClosedBlock: ({ children }: { children: ReactNode }) => <>{children}</>,
  useEntitlements: () => ({ data: null, error: '', loading: false, retry: vi.fn() }),
}))

afterEach(cleanup)

describe('IntegratePage documentation link', () => {
  it('uses the published API wiki instead of a placeholder href', () => {
    render(<IntegratePage />)

    const link = screen.getByRole('link', { name: '接入文档' })
    expect(link.getAttribute('href')).toBe('https://wiki.auth.clya.top')
    expect(link.getAttribute('href')).not.toBe('#')
  })
})
