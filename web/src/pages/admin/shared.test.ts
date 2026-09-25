import { describe, expect, it } from 'vitest'
import { DEFAULT_PAGE_SIZE, parsePageSizeParam } from './shared'

describe('parsePageSizeParam', () => {
  it('只接受分页下拉里的档位，其余回落默认值', () => {
    expect(parsePageSizeParam('50')).toBe(50)
    expect(parsePageSizeParam('100')).toBe(100)
    for (const raw of [null, '', '0', '7', '101', '1000', 'abc', '20.5']) {
      expect(parsePageSizeParam(raw)).toBe(DEFAULT_PAGE_SIZE)
    }
  })
})
