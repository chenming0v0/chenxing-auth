import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type {
  CreatedWalletRedemptionCard,
  WalletRedemptionCardDetail,
  WalletRedemptionCardSummary,
} from '../../api'
import { installCsrfCookie } from '../../test/csrf-cookie'
import { InvitationsWorkspace } from './invitations'

installCsrfCookie()

const CODES_PATH = '/api/v1/admin/registration-invitation-codes'
const CARDS_PATH = '/api/v1/admin/wallet/redemption-codes'

const card: WalletRedemptionCardSummary = {
  id: 21,
  points: 50,
  use_count: 1,
  max_uses: 5,
  label: '内测点券',
  expires_at: null,
  disabled_at: null,
  created_at: '2026-08-23T04:00:00Z',
}

const created: CreatedWalletRedemptionCard = { ...card, id: 22, use_count: 0, code: 'wallet-plain-once' }

const detail: WalletRedemptionCardDetail = {
  ...card,
  uses: [
    { user_id: 12, username: 'stardust', display_name: '星尘', points: 50, redeemed_at: '2026-08-24T02:00:00Z' },
  ],
}

type CapturedRequest = { path: string; method: string }

let requests: CapturedRequest[] = []
let cardsList: WalletRedemptionCardSummary[] = []
let detailResponse: WalletRedemptionCardDetail | null = null
let disableStatus = 200

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function stubFetch() {
  requests = []
  vi.stubGlobal('confirm', vi.fn(() => true) as unknown as typeof confirm)
  vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    const url = String(path)
    requests.push({ path: url, method })
    if (method === 'GET' && url === CODES_PATH) return Promise.resolve(jsonResponse([]))
    if (method === 'GET' && url === CARDS_PATH) return Promise.resolve(jsonResponse(cardsList))
    if (method === 'GET' && url === `${CARDS_PATH}/21`) return Promise.resolve(jsonResponse(detailResponse))
    if (method === 'POST' && url === CARDS_PATH) {
      cardsList = [...cardsList, { ...created }]
      return Promise.resolve(jsonResponse([created], 201))
    }
    if (method === 'POST' && url === `${CARDS_PATH}/21/disable`) {
      return Promise.resolve(jsonResponse({ code: 'redemption_code_not_found' }, disableStatus))
    }
    return Promise.resolve(jsonResponse({ code: 'internal' }, 500))
  })
}

async function openCardsTab() {
  fireEvent.click(await screen.findByRole('tab', { name: '兑换卡' }))
}

describe('兑换卡', () => {
  it('打开抽屉生成后明文只展示一次，并刷新兑换卡列表', async () => {
    cardsList = []
    stubFetch()
    render(<InvitationsWorkspace />)
    fireEvent.click(await screen.findByRole('button', { name: '生成兑换卡' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('面值（辰星点）'), { target: { value: '50' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '生成兑换卡' }))

    await screen.findByText('请立即保存以下兑换码，离开后无法再次查看明文。')
    expect(screen.getByText('wallet-plain-once')).toBeTruthy()
    // 抽屉卸载会解除背景 inert；明文在页面上，必须等 dialog 消失后
    // 复制按钮才进无障碍树，否则 getByRole 会打到仍被 aria-hidden 的节点。
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).toBeNull()
      expect(screen.getByRole('button', { name: '复制全部' })).toBeTruthy()
    })
    expect(screen.getByRole('button', { name: '导出 CSV（明文，仅此次）' })).toBeTruthy()
    await screen.findByText('#22')
    expect(screen.getByText('50 点')).toBeTruthy()
    expect(screen.getByRole('tab', { name: '兑换卡' }).getAttribute('aria-selected')).toBe('true')
    expect(screen.queryByText('还没有邀请码')).toBeNull()
  })

  it('停用失败时显示安全错误、解除 busy，且不把失败当成成功刷新', async () => {
    cardsList = [card]
    disableStatus = 404
    stubFetch()
    render(<InvitationsWorkspace />)
    await openCardsTab()
    const disableButton = await screen.findByRole('button', { name: '停用' })
    fireEvent.click(disableButton)

    await screen.findByText('兑换卡不存在或已失效。')
    expect(window.confirm).toHaveBeenCalledWith('确认停用这张兑换卡吗？停用后不可恢复。')
    await waitFor(() => expect((screen.getByRole('button', { name: '停用' }) as HTMLButtonElement).disabled).toBe(false))
    expect(screen.getByText('#21')).toBeTruthy()
    expect(screen.getByText('1/5')).toBeTruthy()
    expect(screen.getByText('可用')).toBeTruthy()
    expect(requests).toEqual([
      { path: CODES_PATH, method: 'GET' },
      { path: CARDS_PATH, method: 'GET' },
      { path: `${CARDS_PATH}/21/disable`, method: 'POST' },
    ])
  })

  it('点击兑换卡行会打开使用明细', async () => {
    cardsList = [card]
    detailResponse = detail
    stubFetch()
    render(<InvitationsWorkspace />)
    await openCardsTab()
    fireEvent.click(await screen.findByText('#21'))
    await screen.findByText('星尘')
    expect(screen.getByText('stardust')).toBeTruthy()
    expect(requests).toContainEqual({ path: `${CARDS_PATH}/21`, method: 'GET' })
  })
})
