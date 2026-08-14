import { describe, expect, it } from 'vitest'
import { smtpPasswordWrite, validateSmtpPort } from './smtp-panel'

describe('validateSmtpPort', () => {
  it('accepts integers in the u16 port range and serializes them as JSON numbers', () => {
    expect(validateSmtpPort('1')).toEqual({ value: 1 })
    expect(validateSmtpPort('465')).toEqual({ value: 465 })
    expect(validateSmtpPort('65535')).toEqual({ value: 65535 })
    const valid = validateSmtpPort('587')
    if ('error' in valid) throw new Error(valid.error)
    expect(JSON.stringify({ port: valid.value })).toBe('{"port":587}')
  })

  it('rejects empty, non-numeric, non-integer, zero, and negative input instead of falling back to 0', () => {
    expect(validateSmtpPort('')).toEqual({ error: '「SMTP 端口」必须填写大于 0 的整数。' })
    expect(validateSmtpPort('   ')).toEqual({ error: '「SMTP 端口」必须填写大于 0 的整数。' })
    expect(validateSmtpPort('abc')).toEqual({
      error: '「SMTP 端口」不是有效数字（NaN），请填写大于 0 的整数。',
    })
    expect(validateSmtpPort('Infinity')).toEqual({
      error: '「SMTP 端口」必须是有限数字，不能为 Infinity。',
    })
    expect(validateSmtpPort('1.5')).toEqual({ error: '「SMTP 端口」必须填写大于 0 的整数。' })
    expect(validateSmtpPort('0')).toEqual({ error: '「SMTP 端口」必须填写大于 0 的整数。' })
    expect(validateSmtpPort('-1')).toEqual({ error: '「SMTP 端口」必须填写大于 0 的整数。' })
  })

  it('rejects ports above 65535', () => {
    expect(validateSmtpPort('65536')).toEqual({
      error: '「SMTP 端口」超出范围，必须在 1 到 65535 之间。',
    })
  })
})

describe('smtpPasswordWrite', () => {
  it('sends explicit keep/set/clear and never treats empty string as keep', () => {
    expect(smtpPasswordWrite('', false)).toEqual({ password_action: 'keep' })
    expect(smtpPasswordWrite('super-secret-smtp', false)).toEqual({
      password_action: 'set',
      password: 'super-secret-smtp',
    })
    expect(smtpPasswordWrite('', true)).toEqual({ password_action: 'clear' })
    expect(smtpPasswordWrite('super-secret-smtp', true)).toEqual({
      password_action: 'set',
      password: 'super-secret-smtp',
    })
    expect(smtpPasswordWrite('', false)).not.toHaveProperty('password')
    expect(smtpPasswordWrite('', true)).not.toHaveProperty('password')
  })
})
