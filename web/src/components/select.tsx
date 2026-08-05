import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { Icon } from './ui'

/* Native <select> hands its option list to the OS, so <option> can never carry
   the Chenxing theme. This is an ARIA 1.2 select-only combobox: focus stays on
   the trigger and aria-activedescendant tracks the keyboard cursor.

   The popup is portalled with position: fixed because triggers live inside
   overflow-x-auto tables and drawers that would otherwise clip it. */

export type SelectOption = {
  value: string
  label: string
  disabled?: boolean
}

const GAP = 8
const VIEWPORT_MARGIN = 12
const MAX_POPUP_HEIGHT = 288
/* below this the popup would only show a row or two, so flip upward instead */
const MIN_POPUP_HEIGHT = 160
const TYPEAHEAD_RESET_MS = 700

type PopupPosition = {
  left: number
  width: number
  maxHeight: number
  /* anchored by top when opening downward, by bottom when flipped, so the popup
     can grow upward without measuring its own height first */
  top?: number
  bottom?: number
}

type SelectProps = {
  value: string
  onChange: (value: string) => void
  options: SelectOption[]
  disabled?: boolean
  placeholder?: string
  error?: boolean
  className?: string
  'aria-label'?: string
  'aria-labelledby'?: string
}

export function Select({
  value,
  onChange,
  options,
  disabled = false,
  placeholder = '请选择',
  error = false,
  className = '',
  'aria-label': ariaLabel,
  'aria-labelledby': ariaLabelledBy,
}: SelectProps) {
  const [open, setOpen] = useState(false)
  const [activeIndex, setActiveIndex] = useState(-1)
  const [position, setPosition] = useState<PopupPosition | null>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const popupRef = useRef<HTMLDivElement>(null)
  const typeahead = useRef({ query: '', timer: 0 })
  const baseId = useId()

  const selected = options.find((option) => option.value === value)
  const optionId = (index: number) => `${baseId}-option-${index}`
  const selectableIndex = (from: number, step: number) => {
    for (let i = 0; i < options.length; i += 1) {
      const next = (from + step * i + options.length * options.length) % options.length
      if (!options[next].disabled) return next
    }
    return -1
  }

  const measure = useCallback(() => {
    const trigger = triggerRef.current
    if (!trigger) return
    const rect = trigger.getBoundingClientRect()
    const spaceBelow = window.innerHeight - rect.bottom - GAP - VIEWPORT_MARGIN
    const spaceAbove = rect.top - GAP - VIEWPORT_MARGIN
    const flip = spaceBelow < MIN_POPUP_HEIGHT && spaceAbove > spaceBelow
    setPosition({
      left: rect.left,
      width: rect.width,
      maxHeight: Math.max(MIN_POPUP_HEIGHT, Math.min(MAX_POPUP_HEIGHT, flip ? spaceAbove : spaceBelow)),
      ...(flip ? { bottom: window.innerHeight - rect.top + GAP } : { top: rect.bottom + GAP }),
    })
  }, [])

  /* measure before paint so the popup never renders at a stale offset */
  useLayoutEffect(() => {
    if (!open) return
    measure()
  }, [open, measure, options.length])

  useEffect(() => {
    if (!open) return
    const onViewportChange = () => measure()
    /* capture: ancestor scrollers (tables, drawers) don't bubble scroll */
    window.addEventListener('scroll', onViewportChange, true)
    window.addEventListener('resize', onViewportChange)
    return () => {
      window.removeEventListener('scroll', onViewportChange, true)
      window.removeEventListener('resize', onViewportChange)
    }
  }, [open, measure])

  useEffect(() => {
    if (!open) return
    const onPointerDown = (event: MouseEvent) => {
      const target = event.target as Node
      if (triggerRef.current?.contains(target) || popupRef.current?.contains(target)) return
      setOpen(false)
    }
    document.addEventListener('mousedown', onPointerDown)
    return () => document.removeEventListener('mousedown', onPointerDown)
  }, [open])

  useEffect(() => () => window.clearTimeout(typeahead.current.timer), [])

  /* keep the keyboard cursor in view without stealing focus from the trigger */
  useEffect(() => {
    if (!open || activeIndex < 0) return
    popupRef.current?.querySelector(`[data-index="${activeIndex}"]`)?.scrollIntoView({ block: 'nearest' })
  }, [open, activeIndex])

  function openAt(index: number) {
    setActiveIndex(index)
    setOpen(true)
  }

  function commit(option: SelectOption) {
    if (option.disabled) return
    if (option.value !== value) onChange(option.value)
    setOpen(false)
    triggerRef.current?.focus()
  }

  function runTypeahead(key: string) {
    window.clearTimeout(typeahead.current.timer)
    const query = typeahead.current.query + key.toLowerCase()
    typeahead.current.query = query
    typeahead.current.timer = window.setTimeout(() => { typeahead.current.query = '' }, TYPEAHEAD_RESET_MS)
    const match = options.findIndex((option) => !option.disabled && option.label.toLowerCase().startsWith(query))
    if (match === -1) return
    if (open) setActiveIndex(match)
    else openAt(match)
  }

  function handleKeyDown(event: React.KeyboardEvent<HTMLButtonElement>) {
    const currentIndex = activeIndex >= 0 ? activeIndex : options.findIndex((option) => option.value === value)
    switch (event.key) {
      case 'Enter':
      case ' ':
        event.preventDefault()
        if (!open) openAt(currentIndex >= 0 ? currentIndex : selectableIndex(0, 1))
        else if (activeIndex >= 0) commit(options[activeIndex])
        break
      case 'Escape':
        if (!open) return
        event.preventDefault()
        setOpen(false)
        break
      case 'ArrowDown':
        event.preventDefault()
        if (!open) openAt(currentIndex >= 0 ? currentIndex : selectableIndex(0, 1))
        else setActiveIndex(selectableIndex(currentIndex + 1, 1))
        break
      case 'ArrowUp':
        event.preventDefault()
        if (!open) openAt(currentIndex >= 0 ? currentIndex : selectableIndex(options.length - 1, -1))
        else setActiveIndex(selectableIndex(currentIndex - 1, -1))
        break
      case 'Home':
        if (!open) return
        event.preventDefault()
        setActiveIndex(selectableIndex(0, 1))
        break
      case 'End':
        if (!open) return
        event.preventDefault()
        setActiveIndex(selectableIndex(options.length - 1, -1))
        break
      case 'Tab':
        setOpen(false)
        break
      default:
        if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
          event.preventDefault()
          runTypeahead(event.key)
        }
    }
  }

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        role="combobox"
        aria-expanded={open}
        aria-haspopup="listbox"
        aria-controls={open ? `${baseId}-listbox` : undefined}
        aria-activedescendant={open && activeIndex >= 0 ? optionId(activeIndex) : undefined}
        aria-label={ariaLabel}
        aria-labelledby={ariaLabelledBy}
        disabled={disabled}
        className={`chenxing-select-trigger${error ? ' chenxing-field-error' : ''} ${className}`}
        onClick={() => {
          if (open) { setOpen(false); return }
          const current = options.findIndex((option) => option.value === value)
          openAt(current >= 0 ? current : selectableIndex(0, 1))
        }}
        onKeyDown={handleKeyDown}
      >
        <span className={selected ? 'chenxing-select-option-label' : 'chenxing-select-option-label chenxing-select-placeholder'}>
          {selected?.label ?? placeholder}
        </span>
        <Icon name="chevrons-up-down" size={16} className="chenxing-select-caret" />
      </button>

      {open && position
        ? createPortal(
            <div
              ref={popupRef}
              id={`${baseId}-listbox`}
              role="listbox"
              className="chenxing-select-popup"
              style={{
                left: position.left,
                width: position.width,
                maxHeight: position.maxHeight,
                ...(position.top === undefined ? { bottom: position.bottom } : { top: position.top }),
              }}
            >
              {options.map((option, index) => (
                <div
                  key={option.value}
                  id={optionId(index)}
                  role="option"
                  aria-selected={option.value === value}
                  aria-disabled={option.disabled || undefined}
                  data-index={index}
                  className={[
                    'chenxing-select-option',
                    option.value === value ? 'is-selected' : '',
                    index === activeIndex ? 'is-active' : '',
                  ].filter(Boolean).join(' ')}
                  onClick={() => commit(option)}
                  /* mousemove, not mouseenter: keyboard scrolling would otherwise
                     drag the cursor back under a stationary pointer */
                  onMouseMove={() => { if (!option.disabled && index !== activeIndex) setActiveIndex(index) }}
                >
                  <span className="chenxing-select-option-label">{option.label}</span>
                  {option.value === value ? <Icon name="check" size={15} className="chenxing-select-check" /> : null}
                </div>
              ))}
            </div>,
            document.body,
          )
        : null}
    </>
  )
}

type SelectFieldProps = Omit<SelectProps, 'aria-label' | 'aria-labelledby'> & {
  label: string
  icon?: string
  hint?: string
}

export function SelectField({ label, icon, hint, error, ...props }: SelectFieldProps) {
  const labelId = useId()
  /* a plain div, not <label>: a nested <button> would make label clicks toggle
     the popup, so the name is wired with aria-labelledby instead */
  return (
    <div>
      <span id={labelId} className="chenxing-label">{label}</span>
      {icon ? (
        <div className={`chenxing-field-shell${error ? ' chenxing-field-error' : ''}`}>
          <Icon name={icon} className="chenxing-field-icon h-4 w-4" size={16} />
          <Select aria-labelledby={labelId} {...props} />
        </div>
      ) : (
        <Select aria-labelledby={labelId} error={error} {...props} />
      )}
      {hint ? <small className="chenxing-caption mt-1.5 block">{hint}</small> : null}
    </div>
  )
}
