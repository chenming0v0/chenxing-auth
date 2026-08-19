import { describe, expect, it } from 'vitest'
import { LANDING_AUTHORIZATION_CTA_PATH, LANDING_TOKEN_ENDPOINT } from './landing'

describe('landing protocol examples', () => {
  it('sends the authorization CTA to the configured OAuth playground', () => {
    expect(LANDING_AUTHORIZATION_CTA_PATH).toBe('/console/playground')
    expect(LANDING_AUTHORIZATION_CTA_PATH).not.toBe('/oauth/consent')
  })

  it('uses the registered OAuth token endpoint', () => {
    expect(new URL(LANDING_TOKEN_ENDPOINT).pathname).toBe('/oauth/token')
  })
})
