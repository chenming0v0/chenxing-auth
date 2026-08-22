import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { Select } from './select'

function setViewport(width: number, height: number) {
  vi.spyOn(window, 'innerWidth', 'get').mockReturnValue(width)
  vi.spyOn(window, 'innerHeight', 'get').mockReturnValue(height)
}

function setTriggerRect(trigger: HTMLElement, rect: { left: number; top: number; width: number; height: number }) {
  vi.spyOn(trigger, 'getBoundingClientRect').mockReturnValue({
    x: rect.left,
    y: rect.top,
    left: rect.left,
    top: rect.top,
    right: rect.left + rect.width,
    bottom: rect.top + rect.height,
    width: rect.width,
    height: rect.height,
    toJSON: () => ({}),
  })
}

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('Select popup viewport bounds', () => {
  it('uses the actual remaining space instead of forcing the minimum height', () => {
    setViewport(320, 240)
    render(<Select value="one" onChange={() => {}} options={[{ value: 'one', label: 'One' }]} />)
    const trigger = screen.getByRole('combobox')
    setTriggerRect(trigger, { left: 40, top: 100, width: 200, height: 40 })

    fireEvent.click(trigger)

    const popup = screen.getByRole('listbox')
    expect(popup.style.maxHeight).toBe('80px')
    expect(popup.style.top).toBe('148px')
  })

  it('clamps a right-edge popup while preserving the available upward height', () => {
    setViewport(320, 600)
    render(<Select value="one" onChange={() => {}} options={[{ value: 'one', label: 'One' }]} />)
    const trigger = screen.getByRole('combobox')
    setTriggerRect(trigger, { left: 250, top: 400, width: 100, height: 40 })

    fireEvent.click(trigger)

    const popup = screen.getByRole('listbox')
    expect(popup.style.left).toBe('208px')
    expect(popup.style.width).toBe('100px')
    expect(popup.style.maxHeight).toBe('288px')
    expect(popup.style.bottom).toBe('208px')
  })

  it('shrinks a popup wider than the viewport into the viewport margins', () => {
    setViewport(200, 400)
    render(<Select value="one" onChange={() => {}} options={[{ value: 'one', label: 'One' }]} />)
    const trigger = screen.getByRole('combobox')
    setTriggerRect(trigger, { left: 0, top: 100, width: 300, height: 40 })

    fireEvent.click(trigger)

    const popup = screen.getByRole('listbox')
    expect(popup.style.left).toBe('12px')
    expect(popup.style.width).toBe('176px')
  })
})
