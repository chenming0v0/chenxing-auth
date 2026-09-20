import { afterEach, describe, expect, it, vi } from 'vitest'
import { parseResourceServiceSnapshot } from './resource-services-types'
import {
  formatDuration,
  statusPresentation,
  subscriptionSummary,
  visibleSnapshotFields,
} from './resource-services-snapshot'

const NOW = new Date('2026-09-18T00:00:00Z')

afterEach(() => {
  vi.useRealTimers()
})

describe('parseResourceServiceSnapshot', () => {
  it('normalizes a full v1 snapshot and keeps every known field type', () => {
    const snapshot = parseResourceServiceSnapshot({
      schema_version: '1',
      issuer: 'https://provider.example.com',
      uid: 'acct-1001',
      account: 'demo-account-1001',
      name: null,
      status: 'active',
      subscription: { kind: 'expires_at', expires_at: '2026-12-31T23:59:59Z' },
      fields: [
        { key: 'uid', label: 'UID', type: 'text', value: 'acct-1001' },
        { key: 'count', label: '数量', type: 'number', value: 3 },
        { key: 'is_subscribed', label: '已订阅', type: 'boolean', value: true },
        { key: 'device_status', label: '设备状态', type: 'status', value: 'bound' },
        { key: 'expires', label: '到期', type: 'datetime', value: '2026-12-31T23:59:59Z' },
        { key: 'remaining_seconds', label: '剩余订阅', type: 'duration', value: 9071999 },
        { key: 'homepage', label: '主页', type: 'url', value: 'https://provider.example.com/user/1001' },
      ],
      fetched_at: '2026-09-18T00:00:00Z',
      future_key: { nested: true },
    })
    expect(snapshot).not.toBeNull()
    expect(snapshot?.uid).toBe('acct-1001')
    expect(snapshot?.name).toBeNull()
    expect(snapshot?.status).toBe('active')
    expect(snapshot?.subscription).toEqual({ kind: 'expires_at', expires_at: '2026-12-31T23:59:59Z' })
    expect(snapshot?.fields.map((field) => field.type)).toEqual(['text', 'number', 'boolean', 'status', 'datetime', 'duration', 'url'])
    expect(snapshot?.fetched_at).toBe('2026-09-18T00:00:00Z')
  })

  it('drops fields with unknown types or malformed values instead of rendering objects', () => {
    const snapshot = parseResourceServiceSnapshot({
      fields: [
        { key: 'raw', label: '原始', type: 'object', value: { nested: true } },
        { key: 'bad_bool', label: '布尔', type: 'boolean', value: 'yes' },
        { key: 'bad_duration', label: '时长', type: 'duration', value: '3600' },
        { key: 'plain_url', label: '链接', type: 'url', value: 'http://insecure.example.com' },
        { key: 'no_label', type: 'text', value: 'x' },
        'not-an-object',
        { key: 'ok', label: '正常', type: 'text', value: 'fine' },
      ],
    })
    expect(snapshot?.fields).toEqual([{ key: 'ok', label: '正常', type: 'text', value: 'fine' }])
  })

  it('treats an unknown or malformed subscription kind as unknown', () => {
    expect(parseResourceServiceSnapshot({ subscription: { kind: 'trial', ends: 'soon' } })?.subscription).toEqual({ kind: 'unknown' })
    expect(parseResourceServiceSnapshot({ subscription: { kind: 'expires_at' } })?.subscription).toEqual({ kind: 'unknown' })
    expect(parseResourceServiceSnapshot({ subscription: { kind: 'remaining', remaining_seconds: '10' } })?.subscription).toEqual({ kind: 'unknown' })
  })

  it('tolerates a partial legacy snapshot', () => {
    const snapshot = parseResourceServiceSnapshot({ account: 'demo', name: '演示', status: 'weird' })
    expect(snapshot).toEqual({
      uid: null,
      account: 'demo',
      name: '演示',
      status: 'unknown',
      subscription: null,
      fields: [],
      fetched_at: null,
    })
  })

  it('returns null for non-object input', () => {
    expect(parseResourceServiceSnapshot(null)).toBeNull()
    expect(parseResourceServiceSnapshot([])).toBeNull()
    expect(parseResourceServiceSnapshot('snapshot')).toBeNull()
  })
})

describe('subscriptionSummary', () => {
  it('rounds remaining time up to whole days for expires_at', () => {
    const summary = subscriptionSummary({ kind: 'expires_at', expires_at: '2026-12-31T23:59:59Z' }, NOW)
    expect(summary).toEqual({ label: '剩余 105 天', tone: 'success', expiresAt: '2026-12-31T23:59:59.000Z' })
  })

  it('derives the expiry from as_of + remaining_seconds and uses the render-time clock', () => {
    // 抓取时剩余 105 天，10 天后再看应该只剩 95 天
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-09-28T00:00:00Z'))
    const summary = subscriptionSummary({ kind: 'remaining', remaining_seconds: 9071999, as_of: '2026-09-18T00:00:00Z' }, new Date())
    expect(summary.label).toBe('剩余 95 天')
    expect(summary.expiresAt).toBe('2026-12-31T23:59:59.000Z')
  })

  it('warns within a week and marks expired subscriptions', () => {
    expect(subscriptionSummary({ kind: 'expires_at', expires_at: '2026-09-25T00:00:00Z' }, NOW)).toMatchObject({ label: '剩余 7 天', tone: 'warning' })
    expect(subscriptionSummary({ kind: 'expires_at', expires_at: '2026-09-26T00:00:00Z' }, NOW)).toMatchObject({ label: '剩余 8 天', tone: 'success' })
    expect(subscriptionSummary({ kind: 'expires_at', expires_at: '2026-09-18T00:00:00Z' }, NOW)).toMatchObject({ label: '已到期', tone: 'warning' })
    expect(subscriptionSummary({ kind: 'expires_at', expires_at: '2026-01-01T00:00:00Z' }, NOW)).toMatchObject({ label: '已到期', tone: 'warning' })
  })

  it('falls back to 未知 when the timestamp cannot be parsed', () => {
    expect(subscriptionSummary({ kind: 'expires_at', expires_at: 'not-a-date' }, NOW)).toEqual({ label: '未知', tone: 'neutral', expiresAt: null })
  })

  it('maps the static kinds to plain labels', () => {
    expect(subscriptionSummary({ kind: 'permanent' }, NOW)).toEqual({ label: '永久', tone: 'success', expiresAt: null })
    expect(subscriptionSummary({ kind: 'none' }, NOW)).toEqual({ label: '未订阅', tone: 'neutral', expiresAt: null })
    expect(subscriptionSummary({ kind: 'unknown' }, NOW)).toEqual({ label: '未知', tone: 'neutral', expiresAt: null })
  })
})

describe('formatDuration', () => {
  it.each([
    [9071999, '104 天 23 小时'],
    [86400, '1 天 0 小时'],
    [7200, '2 小时'],
    [3599, '59 分钟'],
    [0, '0 分钟'],
    [-5, '0 分钟'],
  ])('formats %d seconds as %s', (seconds, expected) => {
    expect(formatDuration(seconds)).toBe(expected)
  })
})

describe('statusPresentation', () => {
  it('translates the known provider statuses', () => {
    expect(statusPresentation('active')).toEqual({ label: '正常', tone: 'success' })
    expect(statusPresentation('disabled')).toEqual({ label: '已禁用', tone: 'warning' })
    expect(statusPresentation('unknown')).toEqual({ label: '未知', tone: 'neutral' })
    expect(statusPresentation('bound')).toEqual({ label: '已绑定', tone: 'success' })
    expect(statusPresentation('unbound')).toEqual({ label: '未绑定', tone: 'neutral' })
  })

  it('keeps unfamiliar values verbatim and treats a missing status as bound', () => {
    expect(statusPresentation('suspended')).toEqual({ label: 'suspended', tone: 'neutral' })
    expect(statusPresentation(null)).toEqual({ label: '已绑定', tone: 'success' })
  })
})

describe('visibleSnapshotFields', () => {
  const fields = [
    { key: 'uid', label: 'UID', type: 'text' as const, value: 'acct-1001' },
    { key: 'account_status', label: '账号状态', type: 'status' as const, value: 'active' },
    { key: 'is_subscribed', label: '已订阅', type: 'boolean' as const, value: true },
    { key: 'remaining_seconds', label: '剩余订阅', type: 'duration' as const, value: 10 },
    { key: 'device_status', label: '设备状态', type: 'status' as const, value: 'bound' },
  ]

  it('hides header and subscription duplicates when a summary is shown', () => {
    expect(visibleSnapshotFields(fields, true).map((field) => field.key)).toEqual(['device_status'])
  })

  it('keeps subscription fields when there is no summary to replace them', () => {
    expect(visibleSnapshotFields(fields, false).map((field) => field.key)).toEqual(['is_subscribed', 'remaining_seconds', 'device_status'])
  })
})
