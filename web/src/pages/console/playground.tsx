import { useEffect, useState } from 'react'
import { Link } from '../../router'
import { apiFetch, type OwnedOAuthClient } from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Badge, Button, Chip, EmptyState, Field, HudPanel, Icon, Notice, PageIntro } from '../../components/ui'
import { SelectField } from '../../components/select'
import { entitlementState, useEntitlements } from './shared'

export function PlaygroundPage() {
  const selfServiceClosed = entitlementState(useEntitlements()).kind === 'closed'
  const [clients, setClients] = useState<OwnedOAuthClient[]>([])
  const [selectedId, setSelectedId] = useState('')
  const [redirectUri, setRedirectUri] = useState('')
  const [scope, setScope] = useState('openid')
  const [result, setResult] = useState<{ url: string; verifier: string; challenge: string; state: string } | null>(null)
  const [message, setMessage] = useState('')

  useEffect(() => {
    void apiFetch<{ items: OwnedOAuthClient[] }>('/api/v1/auth/oauth-clients')
      .then((response) => {
        setClients(response.items)
        const first = response.items[0]
        if (first) {
          setSelectedId(first.client_id)
          setRedirectUri(first.redirect_uris[0] || '')
          setScope(first.scopes.join(' '))
        }
      })
      .catch((reason: unknown) => setMessage(reason instanceof Error ? reason.message : '应用列表加载失败。'))
  }, [])

  function selectClient(clientId: string) {
    const client = clients.find((item) => item.client_id === clientId)
    setSelectedId(clientId)
    setRedirectUri(client?.redirect_uris[0] || '')
    setScope(client?.scopes.join(' ') || 'openid')
    setResult(null)
    setMessage('')
  }

  function updateRedirectUri(value: string) {
    setRedirectUri(value)
    setResult(null)
  }

  function updateScope(value: string) {
    setScope(value)
    setResult(null)
  }

  async function generate() {
    const client = clients.find((item) => item.client_id === selectedId)
    if (!client || !redirectUri || !scope.trim()) {
      setMessage('请选择应用并填写服务端允许的 Redirect URI 和 Scope。')
      return
    }
    try {
      const random = (size: number) => {
        const bytes = new Uint8Array(size)
        crypto.getRandomValues(bytes)
        return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('')
      }
      const verifier = random(32)
      const state = random(16)
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
      const challenge = btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
      const url = new URL('/oauth/authorize', window.location.origin)
      url.searchParams.set('client_id', client.client_id)
      url.searchParams.set('redirect_uri', redirectUri)
      url.searchParams.set('response_type', 'code')
      url.searchParams.set('scope', scope.trim())
      url.searchParams.set('state', state)
      url.searchParams.set('code_challenge', challenge)
      url.searchParams.set('code_challenge_method', 'S256')
      setResult({ url: url.toString(), verifier, challenge, state })
      setMessage('')
    } catch {
      setMessage('无法生成 PKCE 参数，请检查浏览器加密能力。')
    }
  }

  return (
    <ConsoleLayout>
      <PageIntro eyebrow="// Playground" title="授权测试" description="用真实的授权码 + PKCE 流程验证你的接入配置。" />
      {message ? <div className="mb-4"><Notice tone="warning">{message}</Notice></div> : null}

      {!clients.length ? (
        <HudPanel className="flex min-h-[20rem] flex-col items-center justify-center text-center">
          {/* 未开放自助接入时不引导用户去一个不能提交的注册入口 */}
          {selfServiceClosed ? (
            <EmptyState
              icon="lock-keyhole"
              title="没有可用于测试的应用"
              description="平台未开放自助接入，当前不能自行注册应用。管理员为你分配套餐后即可在这里测试授权流程。"
            />
          ) : (
            <EmptyState
              icon="rocket"
              title="需要先注册一个应用"
              description="测试台会使用你应用的 Client ID 和回调地址来构造真实的授权请求。"
              action={<Link to="/console/integrate" className="chenxing-btn-primary mt-6 px-5 py-2.5"><Icon name="plus" size={16} />前往接入应用</Link>}
            />
          )}
        </HudPanel>
      ) : (
        <HudPanel as="section">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h3 className="chenxing-h3">授权请求配置</h3>
              <p className="chenxing-caption mt-1">按下方参数构造 <span className="chenxing-mono text-[var(--chenxing-cyan)]">/oauth/authorize</span> 请求。</p>
            </div>
            <Badge tone="success"><span className="chenxing-status-dot" />应用在线</Badge>
          </div>
          <div className="mt-6 grid gap-5 sm:grid-cols-2">
            <SelectField
              label="选择应用"
              value={selectedId}
              onChange={selectClient}
              options={clients.map((client) => ({ value: client.client_id, label: client.client_name }))}
            />
            <Field label="Client ID" className="chenxing-mono text-sm" readOnly value={selectedId} />
            <Field label="Redirect URI" className="chenxing-mono text-sm" value={redirectUri} onChange={(event) => updateRedirectUri(event.target.value)} />
            <Field label="Scope" value={scope} onChange={(event) => updateScope(event.target.value)} />
            <Field label="Response Type" className="chenxing-mono text-sm" readOnly value="code" />
            <Field label="Code Challenge Method" className="chenxing-mono text-sm" readOnly value="S256" />
          </div>

          <div className="mt-6 rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.55)] p-4">
            <div className="flex items-center justify-between">
              <span className="chenxing-label mb-0">PKCE 参数</span>
              <button type="button" className="chenxing-link inline-flex items-center gap-1.5" onClick={() => void generate()}>
                <Icon name="refresh-cw" size={16} />重新生成
              </button>
            </div>
            {result ? (
              <div className="mt-3 space-y-2 text-sm">
                <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:gap-3">
                  <span className="chenxing-mono w-40 shrink-0 text-[var(--chenxing-muted-foreground)]">code_verifier</span>
                  <span className="chenxing-mono truncate text-[var(--chenxing-ice)]">{result.verifier}</span>
                </div>
                <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:gap-3">
                  <span className="chenxing-mono w-40 shrink-0 text-[var(--chenxing-muted-foreground)]">code_challenge</span>
                  <span className="chenxing-mono truncate text-[var(--chenxing-ice)]">{result.challenge}</span>
                </div>
              </div>
            ) : <p className="chenxing-caption mt-3">点击重新生成以创建 PKCE 参数与授权 URL。</p>}
          </div>

          {result ? (
            <div className="mt-5">
              <div className="flex items-center justify-between">
                <label className="chenxing-label mb-0">Authorize URL</label>
                <button type="button" className="chenxing-link inline-flex items-center gap-1.5" onClick={() => void navigator.clipboard?.writeText(result.url)}>
                  <Icon name="copy" size={16} />复制
                </button>
              </div>
              <pre className="chenxing-mono mt-2 overflow-x-auto rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.7)] p-4 text-xs leading-relaxed text-[var(--chenxing-ice)]">{result.url}</pre>
              <div className="mt-6 flex flex-wrap items-center gap-3">
                <a className="chenxing-btn-primary" href={result.url} target="_blank" rel="noreferrer"><Icon name="send" size={16} />打开授权端点</a>
                <Chip>state · {result.state.slice(0, 8)}</Chip>
              </div>
            </div>
          ) : (
            <div className="mt-6">
              <Button icon="send" onClick={() => void generate()}>生成授权 URL</Button>
            </div>
          )}
        </HudPanel>
      )}
    </ConsoleLayout>
  )
}
