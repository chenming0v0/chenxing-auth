import { describe, expect, it } from 'vitest'
import { validateSecurityLimitInput } from './security-limits-panel'

describe('validateSecurityLimitInput', () => {
  const maximum = 9_223_372_036_854_775_807n

  it('preserves valid positive integers without a JavaScript safe-integer cap', () => {
    expect(validateSecurityLimitInput('30', '失败次数上限', maximum)).toEqual({ value: '30' })
    expect(validateSecurityLimitInput('9223372036854775807', '失败次数上限', maximum)).toEqual({
      value: '9223372036854775807',
    })
  })

  it('reports NaN, non-finite, and upper-range input separately', () => {
    expect(validateSecurityLimitInput('NaN', '失败次数上限', maximum)).toEqual({
      error: '「失败次数上限」不是有效数字（NaN），请填写大于 0 的整数。',
    })
    expect(validateSecurityLimitInput('1e309', '失败次数上限', maximum)).toEqual({
      error: '「失败次数上限」必须是有限数字，不能为 Infinity。',
    })
    expect(validateSecurityLimitInput('9223372036854775808', '失败次数上限', maximum)).toEqual({
      error: '「失败次数上限」超出范围，必须在 1 到 9223372036854775807 之间。',
    })
  })
})
