import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { StrictMode } from 'react'
import type {
  CreatedInvitationCode,
  InvitationCodeDetail,
  InvitationCodeSummary,
  WalletRedemptionCardSummary,
} from '../../api'
import { installCsrfCookie } from '../../test/csrf-cookie'
import { InvitationsWorkspace } from './invitations'

installCsrfCookie()

const CODES_PATH = '/api/v1/admin/registration-invitation-codes'
const CARDS_PATH = '/api/v1/admin/wallet/redemption-codes'

const singleUse: InvitationCodeSummary = {
  id: 7,
  label: null,
  max_uses: 1,
  use_count: 0,
  expires_at: null,
  disabled_at: null,
  created_at: '2026-08-23T00:00:00Z',
}

const multiUse: InvitationCodeSummary = {
  id: 8,
  label: '内测',
  max_uses: 5,
  use_count: 2,
  expires_at: null,
  disabled_at: null,
  created_at: '2026-08-23T01:00:00Z',
}

const created: CreatedInvitationCode = { ...singleUse, id: 9, code: 'invite-plain-once' }

const detail: InvitationCodeDetail = {
  ...multiUse,
  uses: [
    { user_id: 12, username: 'stardust', display_name: '星尘', used_at: '2026-08-24T02:00:00Z' },
    { user_id: 13, username: 'nova', display_name: null, used_at: '2026-08-24T03:00:00Z' },
  ],
}

type CapturedRequest = { path: string; method: string }
type Deferred<T> = { promise: Promise<T>; resolve: (value: T) => void }

const oldCard: WalletRedemptionCardSummary = {
  id: 30,
  points: 10,
  use_count: 0,
  max_uses: 1,
  label: '旧响应兑换卡',
  expires_at: null,
  disabled_at: null,
  created_at: '2026-08-23T02:00:00Z',
}

const newCard: WalletRedemptionCardSummary = { ...oldCard, id: 31, label: '新响应兑换卡' }

let requests: CapturedRequest[] = []
let list: InvitationCodeSummary[] = []
let cardsList: unknown[] = []
let detailResponse: InvitationCodeDetail | null = null
let disableStatus = 200

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise })
  return { promise, resolve }
}

/**
 * 让指定列表端点按调用顺序返回给定的 deferred，用来构造「B 先返回、A 后返回」。
 * 另一个列表端点返回空数组，不干扰断言。
 */
function stubDeferredList(target: string, pending: Array<Deferred<Response>>) {
  let index = 0
  requests = []
  vi.stubGlobal('confirm', vi.fn(() => true) as unknown as typeof confirm)
  vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    const url = String(path)
    requests.push({ path: url, method })
    if (method === 'GET' && url === target) {
      const next = pending[index]
      index += 1
      return next ? next.promise : new Promise<Response>(() => {})
    }
    if (method === 'GET' && (url === CODES_PATH || url === CARDS_PATH)) {
      return Promise.resolve(jsonResponse([]))
    }
    return Promise.resolve(jsonResponse({ code: 'internal' }, 500))
  })
  return () => index
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
    if (method === 'GET' && url === CODES_PATH) return Promise.resolve(jsonResponse(list))
    if (method === 'GET' && url === CARDS_PATH) return Promise.resolve(jsonResponse(cardsList))
    if (method === 'GET' && url === `${CODES_PATH}/8`) return Promise.resolve(jsonResponse(detailResponse))
    if (method === 'POST' && url === CODES_PATH) {
      list = [...list, { ...created }]
      return Promise.resolve(jsonResponse([created], 201))
    }
    if (method === 'POST' && url === `${CODES_PATH}/7/disable`) {
      return Promise.resolve(jsonResponse({ code: 'invitation_code_not_found' }, disableStatus))
    }
    return Promise.resolve(jsonResponse({ code: 'internal' }, 500))
  })
}

describe('邀请码独立页', () => {
  it('页头有生成按钮，列表有导出；表单字段要点开抽屉才出现', async () => {
    list = [singleUse]
    cardsList = []
    stubFetch()
    render(<InvitationsWorkspace />)
    await screen.findByText('#7')
    expect(screen.getByRole('button', { name: '生成邀请码' })).toBeTruthy()
    expect(screen.getByRole('button', { name: '生成兑换卡' })).toBeTruthy()
    expect(screen.getByRole('button', { name: '导出列表 CSV' })).toBeTruthy()
    expect(screen.queryByLabelText('生成数量')).toBeNull()
    expect(screen.queryByLabelText('每码可用次数')).toBeNull()
    expect(screen.queryByLabelText('过期时间')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: '生成邀请码' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByLabelText('生成数量')).toBeTruthy()
    expect(within(dialog).getByLabelText('每码可用次数')).toBeTruthy()
    expect(within(dialog).getByLabelText('标签')).toBeTruthy()
    expect(within(dialog).getByLabelText('过期时间')).toBeTruthy()
  })

  it('生成后提示明文只展示一次，并提供复制全部与明文导出', async () => {
    list = []
    cardsList = []
    stubFetch()
    render(<InvitationsWorkspace />)
    fireEvent.click(await screen.findByRole('button', { name: '生成邀请码' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.submit(dialog.querySelector('form') as HTMLFormElement)
    await screen.findByText('请立即保存以下邀请码，离开后无法再次查看明文。')
    expect(screen.getByText('invite-plain-once')).toBeTruthy()
    // 抽屉卸载会解除背景 inert；明文在页面上，必须等 dialog 消失后
    // 复制按钮才进无障碍树，否则 getByRole 会打到仍被 aria-hidden 的节点。
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).toBeNull()
      expect(screen.getByRole('button', { name: '复制全部' })).toBeTruthy()
    })
    expect(screen.getByRole('button', { name: '导出 CSV（明文，仅此次）' })).toBeTruthy()

    fireEvent.click(screen.getByRole('tab', { name: '兑换卡' }))
    await screen.findByText('还没有兑换卡')
    expect(screen.queryByText('请立即保存以下邀请码，离开后无法再次查看明文。')).toBeNull()
    fireEvent.click(screen.getByRole('tab', { name: '邀请码' }))
    expect(screen.getByText('请立即保存以下邀请码，离开后无法再次查看明文。')).toBeTruthy()
  })

  it('停用失败时显示安全错误、解除 busy，且不把失败当成成功刷新', async () => {
    list = [singleUse]
    cardsList = []
    disableStatus = 404
    stubFetch()
    render(<InvitationsWorkspace />)
    const disableButton = await screen.findByRole('button', { name: '停用' })
    fireEvent.click(disableButton)

    await screen.findByText('邀请码不存在或已失效。')
    expect(window.confirm).toHaveBeenCalledWith('确认停用这个邀请码吗？停用后不可恢复。')
    await waitFor(() => expect((screen.getByRole('button', { name: '停用' }) as HTMLButtonElement).disabled).toBe(false))
    expect(screen.getByText('#7')).toBeTruthy()
    expect(screen.getByText('0/1')).toBeTruthy()
    expect(screen.getByText('可用')).toBeTruthy()
    expect(requests).toEqual([
      { path: CODES_PATH, method: 'GET' },
      { path: `${CODES_PATH}/7/disable`, method: 'POST' },
    ])
  })

  it('点击多次可用的邀请码行会打开使用明细', async () => {
    list = [multiUse]
    cardsList = []
    detailResponse = detail
    stubFetch()
    render(<InvitationsWorkspace />)
    fireEvent.click(await screen.findByText('#8'))
    await screen.findByText('星尘')
    expect(screen.getByText('stardust')).toBeTruthy()
    expect(screen.getByText('nova')).toBeTruthy()
    expect(requests).toContainEqual({ path: `${CODES_PATH}/8`, method: 'GET' })
  })

  it('没有使用记录时显示空态', async () => {
    list = [multiUse]
    cardsList = []
    detailResponse = { ...multiUse, uses: [] }
    stubFetch()
    render(<InvitationsWorkspace />)
    fireEvent.click(await screen.findByText('#8'))
    await screen.findByText('还没有人使用这个邀请码')
  })

  it('同一时刻只有一张表，切换后另一张的表头和空态消失', async () => {
    list = []
    cardsList = []
    stubFetch()
    render(<InvitationsWorkspace />)
    await screen.findByText('还没有邀请码')
    expect(screen.getByText('生成一批邀请码后，会显示在这里。')).toBeTruthy()
    expect(screen.queryByText('还没有兑换卡')).toBeNull()
    expect(screen.queryByText('面值')).toBeNull()
    expect(document.querySelectorAll('table')).toHaveLength(1)

    fireEvent.click(screen.getByRole('tab', { name: '兑换卡' }))
    await screen.findByText('还没有兑换卡')
    expect(screen.getByText('生成一批兑换卡后，会显示在这里。')).toBeTruthy()
    expect(screen.queryByText('还没有邀请码')).toBeNull()
    expect(screen.queryByText('生成一批邀请码后，会显示在这里。')).toBeNull()
    expect(document.querySelectorAll('table')).toHaveLength(1)
  })
})

describe('邀请与兑换页签键盘导航（#691）', () => {
  it('方向键在页签间移动焦点并切换列表', async () => {
    list = []
    cardsList = []
    stubFetch()
    render(<InvitationsWorkspace />)
    const codesTab = await screen.findByRole('tab', { name: '邀请码' })
    const cardsTab = screen.getByRole('tab', { name: '兑换卡' })
    expect(codesTab.getAttribute('aria-selected')).toBe('true')
    expect(codesTab.tabIndex).toBe(0)
    expect(cardsTab.tabIndex).toBe(-1)

    codesTab.focus()
    fireEvent.keyDown(codesTab, { key: 'ArrowRight' })

    await screen.findByText('还没有兑换卡')
    expect(screen.getByRole('tab', { name: '兑换卡' }).getAttribute('aria-selected')).toBe('true')
    expect(document.activeElement).toBe(screen.getByRole('tab', { name: '兑换卡' }))
    expect(screen.getByRole('tab', { name: '兑换卡' }).tabIndex).toBe(0)
    expect(screen.getByRole('tab', { name: '邀请码' }).tabIndex).toBe(-1)
    expect(screen.getByRole('tabpanel').getAttribute('aria-labelledby')).toBe('invitations-cards-tab')
  })

  it('Home / End 与方向键回环让两个页签都能由键盘到达', async () => {
    list = []
    cardsList = []
    stubFetch()
    render(<InvitationsWorkspace />)
    const codesTab = await screen.findByRole('tab', { name: '邀请码' })
    codesTab.focus()
    fireEvent.keyDown(codesTab, { key: 'End' })
    await screen.findByText('还没有兑换卡')
    expect(document.activeElement).toBe(screen.getByRole('tab', { name: '兑换卡' }))

    fireEvent.keyDown(screen.getByRole('tab', { name: '兑换卡' }), { key: 'Home' })
    await screen.findByText('还没有邀请码')
    expect(document.activeElement).toBe(screen.getByRole('tab', { name: '邀请码' }))

    fireEvent.keyDown(screen.getByRole('tab', { name: '邀请码' }), { key: 'ArrowLeft' })
    await screen.findByText('还没有兑换卡')
    expect(screen.getByRole('tab', { name: '兑换卡' }).getAttribute('aria-selected')).toBe('true')
  })

  it('非 tabs 模式的按键不切换页签', async () => {
    list = []
    cardsList = []
    stubFetch()
    render(<InvitationsWorkspace />)
    const codesTab = await screen.findByRole('tab', { name: '邀请码' })
    codesTab.focus()
    fireEvent.keyDown(codesTab, { key: 'ArrowDown' })
    fireEvent.keyDown(codesTab, { key: 'Enter' })

    expect(screen.getByRole('tab', { name: '邀请码' }).getAttribute('aria-selected')).toBe('true')
    expect(screen.getByRole('tab', { name: '兑换卡' }).getAttribute('aria-selected')).toBe('false')
  })
})

describe('邀请与兑换并发列表加载（#688）', () => {
  it('StrictMode 双请求下，后返回的旧邀请码列表不覆盖已渲染的新列表', async () => {
    const requestA = deferred<Response>()
    const requestB = deferred<Response>()
    stubDeferredList(CODES_PATH, [requestA, requestB])
    render(<StrictMode><InvitationsWorkspace /></StrictMode>)
    await waitFor(() => expect(requests.filter((item) => item.path === CODES_PATH)).toHaveLength(2))

    await act(async () => {
      requestB.resolve(jsonResponse([multiUse]))
      await requestB.promise
    })
    expect(await screen.findByText('#8')).toBeTruthy()

    await act(async () => {
      requestA.resolve(jsonResponse([singleUse]))
      await requestA.promise
    })
    expect(screen.getByText('#8')).toBeTruthy()
    expect(screen.queryByText('#7')).toBeNull()
  })

  it('旧邀请码请求失败时不写入错误文案，也不把列表清空', async () => {
    const requestA = deferred<Response>()
    const requestB = deferred<Response>()
    stubDeferredList(CODES_PATH, [requestA, requestB])
    render(<StrictMode><InvitationsWorkspace /></StrictMode>)
    await waitFor(() => expect(requests.filter((item) => item.path === CODES_PATH)).toHaveLength(2))

    await act(async () => {
      requestB.resolve(jsonResponse([multiUse]))
      await requestB.promise
    })
    expect(await screen.findByText('#8')).toBeTruthy()

    await act(async () => {
      requestA.resolve(jsonResponse({ code: 'internal' }, 500))
      await requestA.promise
    })
    expect(screen.queryByText('服务暂时不可用，请稍后重试。')).toBeNull()
    expect(screen.getByText('#8')).toBeTruthy()
    expect(screen.queryByText('还没有邀请码')).toBeNull()
  })

  it('兑换卡列表的重复加载同样只接受最新一次响应', async () => {
    const requestA = deferred<Response>()
    const requestB = deferred<Response>()
    const cardsCalls = stubDeferredList(CARDS_PATH, [requestA, requestB])
    render(<InvitationsWorkspace />)
    await screen.findByText('还没有邀请码')

    // 兑换卡仍在途时来回切页签：cards 还是 null，会再发一次请求，两次重叠。
    fireEvent.click(screen.getByRole('tab', { name: '兑换卡' }))
    fireEvent.click(screen.getByRole('tab', { name: '邀请码' }))
    fireEvent.click(screen.getByRole('tab', { name: '兑换卡' }))
    await waitFor(() => expect(cardsCalls()).toBe(2))

    await act(async () => {
      requestB.resolve(jsonResponse([newCard]))
      await requestB.promise
    })
    expect(await screen.findByText('#31')).toBeTruthy()

    await act(async () => {
      requestA.resolve(jsonResponse([oldCard]))
      await requestA.promise
    })
    expect(screen.getByText('#31')).toBeTruthy()
    expect(screen.queryByText('#30')).toBeNull()
  })
})
