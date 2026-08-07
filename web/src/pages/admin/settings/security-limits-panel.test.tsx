import { describe, expect, it } from 'vitest'
import { validateSecurityLimitInput } from './security-limits-panel'

describe('validateSecurityLimitInput', () => {
  const maximum = Number.MAX_SAFE_INTEGER

  it('accepts safe positive integers and serializes them as JSON numbers', () => {
    const valid = validateSecurityLimitInput('30', '失败次数上限', maximum)
    expect(valid).toEqual({ value: 30 })
    if ('error' in valid) throw new Error(valid.error)
    expect(JSON.stringify({ failure_limit: valid.value })).toBe('{"failure_limit":30}')

    const largest = validateSecurityLimitInput(String(maximum), '失败次数上限', maximum)
    expect(largest).toEqual({
      value: maximum,
    })
    if ('error' in largest) throw new Error(largest.error)
    expect(JSON.stringify({ failure_limit: largest.value })).toBe('{"failure_limit":9007199254740991}')
  })

  it('rejects empty, NaN, non-finite, non-integer, and non-positive input', () => {
    expect(validateSecurityLimitInput('', '失败次数上限', maximum)).toEqual({
      error: '「失败次数上限」必须填写大于 0 的整数。',
    })
    expect(validateSecurityLimitInput('NaN', '失败次数上限', maximum)).toEqual({
      error: '「失败次数上限」不是有效数字（NaN），请填写大于 0 的整数。',
    })
    expect(validateSecurityLimitInput('Infinity', '失败次数上限', maximum)).toEqual({
      error: '「失败次数上限」必须是有限数字，不能为 Infinity。',
    })
    expect(validateSecurityLimitInput('1.5', '失败次数上限', maximum)).toEqual({
      error: '「失败次数上限」必须填写大于 0 的整数。',
    })
    expect(validateSecurityLimitInput('0', '失败次数上限', maximum)).toEqual({
      error: '「失败次数上限」必须填写大于 0 的整数。',
    })
    expect(validateSecurityLimitInput('-1', '失败次数上限', maximum)).toEqual({
      error: '「失败次数上限」必须填写大于 0 的整数。',
    })
  })

  it('rejects unsafe integers and enforces the QPS maximum', () => {
    expect(validateSecurityLimitInput('9007199254740992', '失败次数上限', maximum)).toEqual({
      error: '「失败次数上限」超出 JavaScript 安全整数范围，最大为 9007199254740991。',
    })
    expect(validateSecurityLimitInput('1000', '未认证来源 QPS 上限', 1_000)).toEqual({ value: 1000 })
    expect(validateSecurityLimitInput('1001', '未认证来源 QPS 上限', 1_000)).toEqual({
      error: '「未认证来源 QPS 上限」超出范围，必须在 1 到 1000 之间。',
    })
  })
})
