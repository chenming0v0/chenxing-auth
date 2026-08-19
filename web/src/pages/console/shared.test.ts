import { describe, expect, it } from 'vitest'
import type { EntitlementsResponse } from '../../api'
import { entitlementState } from './shared'
import { formatQuota } from './developer-shared'

const withPlan: EntitlementsResponse = {
  plan: { code: 'basic', name: '基础版', description: null, validity: 'permanent' },
  entitlements: [{ key: 'oauth_clients', label: 'OAuth 应用', used: 1, limit: 2, remaining: 1 }],
}
const withoutPlan: EntitlementsResponse = { plan: null, entitlements: [] }

describe('entitlementState', () => {
  it('reports closed when plan is null (self-service not open)', () => {
    const state = entitlementState({ data: withoutPlan, error: '', loading: false })
    expect(state.kind).toBe('closed')
  })

  it('reports ready with a non-null plan narrowed for callers', () => {
    const state = entitlementState({ data: withPlan, error: '', loading: false })
    expect(state.kind).toBe('ready')
    if (state.kind !== 'ready') throw new Error('expected ready')
    expect(state.plan.code).toBe('basic')
  })

  it('reports loading before the first response arrives', () => {
    expect(entitlementState({ data: null, error: '', loading: true }).kind).toBe('loading')
  })

  it('reports failed with the request error when no data was ever loaded', () => {
    const state = entitlementState({ data: null, error: '网络连接不可用，请稍后重试。', loading: false })
    expect(state).toEqual({ kind: 'failed', message: '网络连接不可用，请稍后重试。' })
  })

  it('keeps the closed state even if a later retry fails', () => {
    // 已有数据优先：重试失败不应把「未开放自助接入」退回成错误页
    const state = entitlementState({ data: withoutPlan, error: '服务暂时不可用，请稍后重试。', loading: false })
    expect(state.kind).toBe('closed')
  })

  it('falls back to a generic message when the failure carries no text', () => {
    const state = entitlementState({ data: null, error: '', loading: false })
    expect(state).toEqual({ kind: 'failed', message: '权益数据加载失败。' })
  })
})

describe('formatQuota', () => {
  it('renders numeric limits as-is', () => {
    expect(formatQuota({ quota: { daily_used: 3, daily_limit: 100, monthly_used: 12, monthly_limit: 2000 } }))
      .toBe('今日 3/100 · 本月 12/2000')
  })

  it('renders no-plan limits as unavailable', () => {
    expect(formatQuota({ quota: { daily_used: 0, daily_limit: null, monthly_used: 0, monthly_limit: null } }))
      .toBe('今日 不可用 · 本月 不可用')
  })

  it('renders an unlimited monthly limit only for an effective plan', () => {
    expect(formatQuota({ quota: { daily_used: 3, daily_limit: 100, monthly_used: 12, monthly_limit: null } }))
      .toBe('今日 3/100 · 本月 12/∞')
  })
})
