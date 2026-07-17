/**
 * a11y.ts — Accessibility helpers (WCAG 2.1 AA)
 *
 * Provides:
 *   - Focus management (trap, restore)
 *   - ARIA live region helpers
 *   - Reduced motion detection
 *   - Announce function for screen readers
 *   - Skip-to-content link generator
 */

// ---- Focus Management ----

/**
 * Traps focus within a container element (for modals, dialogs).
 * Returns a cleanup function that restores focus to the previously active element.
 */
export function trapFocus(container: HTMLElement): () => void {
  const previousActive = document.activeElement as HTMLElement | null;

  const focusableSelector =
    'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

  function handleKeyDown(e: KeyboardEvent) {
    if (e.key !== "Tab") return;

    const focusable = container.querySelectorAll<HTMLElement>(focusableSelector);
    if (focusable.length === 0) return;

    const first = focusable[0];
    const last = focusable[focusable.length - 1];

    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }

  // Focus the first focusable element on open
  requestAnimationFrame(() => {
    const first = container.querySelector<HTMLElement>(focusableSelector);
    first?.focus();
  });

  document.addEventListener("keydown", handleKeyDown);

  return () => {
    document.removeEventListener("keydown", handleKeyDown);
    previousActive?.focus();
  };
}

// ---- ARIA Live Region ----

let liveRegion: HTMLDivElement | null = null;

function ensureLiveRegion(): HTMLDivElement {
  if (!liveRegion) {
    liveRegion = document.createElement("div");
    liveRegion.setAttribute("aria-live", "polite");
    liveRegion.setAttribute("aria-atomic", "true");
    liveRegion.className = "sr-only";
    document.body.appendChild(liveRegion);
  }
  return liveRegion;
}

/**
 * Announces a message to screen readers via an ARIA live region.
 * Use for dynamic content changes, errors, and success messages.
 */
export function announce(message: string, priority: "polite" | "assertive" = "polite"): void {
  const region = ensureLiveRegion();
  region.setAttribute("aria-live", priority);

  // Clear and re-set to ensure announcement even if same text
  region.textContent = "";
  requestAnimationFrame(() => {
    region.textContent = message;
  });
}

// ---- Reduced Motion ----

const motionQuery = typeof window !== "undefined"
  ? window.matchMedia("(prefers-reduced-motion: reduce)")
  : null;

export function prefersReducedMotion(): boolean {
  return motionQuery?.matches ?? false;
}

export function onReducedMotionChange(callback: (reduced: boolean) => void): () => void {
  motionQuery?.addEventListener("change", (e) => callback(e.matches));
  return () => motionQuery?.removeEventListener("change", (e) => callback(e.matches));
}

// ---- Skip-to-content ----

/**
 * Generates props for a skip-to-content link (place as first focusable element).
 * The target element should have id="main-content".
 */
export function skipToContentProps() {
  return {
    href: "#main-content",
    className:
      "sr-only focus:not-sr-only focus:fixed focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-primary focus:text-primary-foreground focus:rounded-md focus:outline-none",
    children: "Saltar al contenido principal",
  };
}

// ---- Focus indicator utility ----

/**
 * Returns class names for visible focus indicators (WCAG 2.1 AA 2.4.7).
 * Use with :focus-visible via Tailwind's focus-visible: variant.
 */
export const focusVisibleClasses =
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2";
