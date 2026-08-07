import { beforeEach } from 'vitest'

beforeEach(() => {
  document.cookie = 'chenxing_csrf=test-csrf-token; path=/'
})
