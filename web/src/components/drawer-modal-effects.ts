type OverflowSnapshot = {
  element: HTMLElement
  value: string
  priority: string
}

type BackgroundSnapshot = {
  element: HTMLElement
  inert: string | null
  inertProperty: boolean
  ariaHidden: string | null
}

function backgroundBranches(container: HTMLElement): HTMLElement[] {
  const background: HTMLElement[] = []
  let branch: HTMLElement | null = container

  // Keep the branch containing the drawer active and disable each sibling branch.
  while (branch && branch !== document.body) {
    const parent: HTMLElement | null = branch.parentElement
    if (!parent) break
    for (const sibling of parent.children) {
      if (sibling !== branch && sibling instanceof HTMLElement) background.push(sibling)
    }
    branch = parent
  }

  return background
}

function restoreAttribute(element: HTMLElement, name: string, value: string | null) {
  if (value === null) element.removeAttribute(name)
  else element.setAttribute(name, value)
}

export function activateDrawerModal(container: HTMLElement) {
  const overflow: OverflowSnapshot[] = [document.documentElement, document.body].map((element) => ({
    element,
    value: element.style.getPropertyValue('overflow'),
    priority: element.style.getPropertyPriority('overflow'),
  }))
  const background: BackgroundSnapshot[] = backgroundBranches(container).map((element) => ({
    element,
    inert: element.getAttribute('inert'),
    inertProperty: element.inert === true,
    ariaHidden: element.getAttribute('aria-hidden'),
  }))

  for (const { element } of overflow) element.style.setProperty('overflow', 'hidden')
  for (const { element } of background) {
    element.setAttribute('inert', '')
    element.inert = true
    element.setAttribute('aria-hidden', 'true')
  }

  return () => {
    for (const { element, inert, inertProperty, ariaHidden } of background) {
      element.inert = inertProperty
      restoreAttribute(element, 'inert', inert)
      restoreAttribute(element, 'aria-hidden', ariaHidden)
    }
    for (const { element, value, priority } of overflow) {
      if (value) element.style.setProperty('overflow', value, priority)
      else element.style.removeProperty('overflow')
    }
  }
}
