import { describe, expect, it, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import type { FormEvent } from 'react'
import { Button, Chip, HudPanel } from './ui'

// 多个用例渲染相同文案，不清理会让 getByText 命中多个节点。
afterEach(cleanup)

describe('HudPanel', () => {
  it('renders a div by default with chenxing-hud-panel class', () => {
    render(<HudPanel>测试内容</HudPanel>)
    const panel = screen.getByText('测试内容')
    expect(panel.tagName).toBe('DIV')
    expect(panel.className).toContain('chenxing-hud-panel')
  })

  it('renders as section when as="section" is passed', () => {
    render(<HudPanel as="section">测试内容</HudPanel>)
    const panel = screen.getByText('测试内容')
    expect(panel.tagName).toBe('SECTION')
    expect(panel.className).toContain('chenxing-hud-panel')
  })

  it('renders as article when as="article" is passed', () => {
    render(<HudPanel as="article">测试内容</HudPanel>)
    const panel = screen.getByText('测试内容')
    expect(panel.tagName).toBe('ARTICLE')
    expect(panel.className).toContain('chenxing-hud-panel')
  })

  it('renders as form when as="form" is passed', () => {
    render(<HudPanel as="form">测试内容</HudPanel>)
    const panel = screen.getByText('测试内容')
    expect(panel.tagName).toBe('FORM')
    expect(panel.className).toContain('chenxing-hud-panel')
  })

  it('appends additional className while keeping chenxing-hud-panel', () => {
    render(<HudPanel className="mt-6 !p-4">测试内容</HudPanel>)
    const panel = screen.getByText('测试内容')
    // chenxing-hud-panel 在前，追加的类名在后，用空格分隔
    expect(panel.className).toBe('chenxing-hud-panel mt-6 !p-4')
  })

  it('does not deduplicate chenxing-hud-panel when passed in className', () => {
    // 用户不应再手写该类，但万一写了，组件不做去重（CSS 对重复类名无影响）
    render(<HudPanel className="chenxing-hud-panel extra">测试内容</HudPanel>)
    const panel = screen.getByText('测试内容')
    // 模板字面量 `chenxing-hud-panel ${className}` 会产生重复，但浏览器 CSS 引擎会忽略重复类
    expect(panel.className).toBe('chenxing-hud-panel chenxing-hud-panel extra')
  })

  it('forwards aria-label and role attributes', () => {
    render(
      <HudPanel role="region" aria-label="测试区域">
        测试内容
      </HudPanel>,
    )
    const panel = screen.getByRole('region', { name: '测试区域' })
    expect(panel).toBeTruthy()
    expect(panel.textContent).toBe('测试内容')
  })

  it('forwards aria-live for live regions', () => {
    render(
      <HudPanel role="region" aria-live="polite" aria-label="动态消息">
        消息内容
      </HudPanel>,
    )
    const panel = screen.getByRole('region', { name: '动态消息' })
    expect(panel.getAttribute('aria-live')).toBe('polite')
  })

  it('forwards onSubmit for form elements', () => {
    let submitted = false
    const handleSubmit = (event: FormEvent) => {
      event.preventDefault()
      submitted = true
    }
    render(
      <HudPanel as="form" onSubmit={handleSubmit}>
        <button type="submit">提交</button>
      </HudPanel>,
    )
    const button = screen.getByRole('button', { name: '提交' })
    const form = button.parentElement as HTMLFormElement
    expect(form.tagName).toBe('FORM')
    // 触发原生表单提交事件，handleSubmit 会阻止默认行为
    form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
    expect(submitted).toBe(true)
  })

  it('preserves className with empty string (renders with trailing space)', () => {
    // 原实现 `chenxing-hud-panel ${className}` 当 className='' 时产生尾随空格
    // 这是既有行为，不影响 CSS 渲染（浏览器忽略类名列表的多余空格）
    render(<HudPanel>测试内容</HudPanel>)
    const panel = screen.getByText('测试内容')
    // 模板字面量 `chenxing-hud-panel ` 会产生尾随空格
    expect(panel.className).toBe('chenxing-hud-panel ')
  })

  it('supports semantic aside element', () => {
    render(<HudPanel as="aside">侧边栏内容</HudPanel>)
    const panel = screen.getByText('侧边栏内容')
    expect(panel.tagName).toBe('ASIDE')
    expect(panel.className).toContain('chenxing-hud-panel')
  })
})

describe('Chip remove control target size（WCAG 2.5.8, #229）', () => {
  it('移除按钮带 24x24 命中区类，且图标保持 12px 紧凑尺寸', () => {
    render(<Chip onRemove={() => {}}>example.com</Chip>)
    const button = screen.getByRole('button', { name: '移除' })
    // 命中区由显式尺寸类保证；jsdom 不做布局，断言类名而非 getBoundingClientRect
    expect(button.className).toContain('h-6')
    expect(button.className).toContain('w-6')
    // 视觉上图标仍然紧凑（lucide 以 width/height 属性承载 size）
    expect(button.querySelector('svg')?.getAttribute('width')).toBe('12')
  })

  it('未提供 onRemove 时不渲染移除按钮', () => {
    render(<Chip>state · abc</Chip>)
    expect(screen.queryByRole('button')).toBeNull()
  })
})

describe('Button aria-disabled', () => {
  it('keeps the button focusable and blocks the click handler', () => {
    let clicks = 0
    render(<Button aria-disabled onClick={() => { clicks += 1 }}>注册新应用</Button>)
    const button = screen.getByRole('button', { name: '注册新应用' })
    // 非 disabled：键盘和读屏能到达按钮，从而读到 aria-describedby 的禁用原因
    expect(button.hasAttribute('disabled')).toBe(false)
    expect(button.getAttribute('aria-disabled')).toBe('true')
    button.click()
    expect(clicks).toBe(0)
  })

  it('still fires onClick when not aria-disabled', () => {
    let clicks = 0
    render(<Button onClick={() => { clicks += 1 }}>注册新应用</Button>)
    screen.getByRole('button', { name: '注册新应用' }).click()
    expect(clicks).toBe(1)
  })

  it('does not bubble the click to a parent handler when aria-disabled (#402)', () => {
    let parentClicks = 0
    render(
      <div onClick={() => { parentClicks += 1 }}>
        <Button aria-disabled onClick={() => {}}>注册新应用</Button>
      </div>,
    )
    screen.getByRole('button', { name: '注册新应用' }).click()
    expect(parentClicks).toBe(0)
  })

  it('still bubbles to a parent handler when not aria-disabled', () => {
    let parentClicks = 0
    render(
      <div onClick={() => { parentClicks += 1 }}>
        <Button onClick={() => {}}>注册新应用</Button>
      </div>,
    )
    screen.getByRole('button', { name: '注册新应用' }).click()
    expect(parentClicks).toBe(1)
  })
})
