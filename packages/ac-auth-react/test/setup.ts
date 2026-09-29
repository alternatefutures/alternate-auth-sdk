import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

afterEach(() => {
  cleanup();
});

// jsdom lacks a few DOM APIs Radix relies on.
if (typeof globalThis.requestAnimationFrame !== 'function') {
  globalThis.requestAnimationFrame = (cb: FrameRequestCallback) => setTimeout(() => cb(performance.now()), 0) as unknown as number;
  globalThis.cancelAnimationFrame = (id: number) => clearTimeout(id);
}
if (typeof globalThis.ResizeObserver !== 'function') {
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver;
}
for (const name of ['hasPointerCapture', 'releasePointerCapture', 'setPointerCapture', 'scrollIntoView'] as const) {
  if (typeof (Element.prototype as unknown as Record<string, unknown>)[name] !== 'function') {
    Object.defineProperty(Element.prototype, name, { value: () => false, configurable: true });
  }
}
