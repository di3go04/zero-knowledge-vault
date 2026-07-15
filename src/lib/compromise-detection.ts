"use client";

export interface CompromiseCheck {
  isCompromised: boolean;
  issues: string[];
}

export function checkDeviceCompromise(): CompromiseCheck {
  const issues: string[] = [];

  try {
    if (typeof window === "undefined") return { isCompromised: false, issues: [] };

    const nav = navigator as any;

    if (navigator.platform?.toLowerCase().includes("android") && typeof (window as any).Java !== "undefined") {
      issues.push("root: Java bridge detected (Android root)");
    }

    if (typeof (window as any).objc_getClass === "function") {
      issues.push("jailbreak: Objective-C bridge detected (iOS jailbreak)");
    }

    if (typeof (window as any).cp_codesign === "function") {
      issues.push("jailbreak: code signing check bypass detected");
    }

    try {
      if (typeof (window as any).Cydia !== "undefined" || typeof (window as any).cydia !== "undefined") {
        issues.push("jailbreak: Cydia detected");
      }
    } catch { /* no-op */ }

    try {
      if (typeof (window as any).MobileSubstrate !== "undefined" || typeof (window as any).Substrate !== "undefined") {
        issues.push("jailbreak: MobileSubstrate detected");
      }
    } catch { /* no-op */ }

    if (typeof nav?.webdriver !== "undefined" && nav.webdriver) {
      issues.push("automation: WebDriver detected (automated access)");
    }

    try {
      const el = document.createElement("div");
      Object.defineProperty(el, "offsetHeight", { get: () => issues.push("debug: iframe detection triggered") });
      void el.offsetHeight;
    } catch { /* no-op */ }

    try {
      const start = performance.now();
      debugger;
      const elapsed = performance.now() - start;
      if (elapsed > 100) {
        issues.push("debug: devtools detected (debugger statement pause)");
      }
    } catch { /* no-op */ }

    if (!navigator.hardwareConcurrency || navigator.hardwareConcurrency < 2) {
      issues.push("sandbox: low CPU core count (possible sandbox/emulator)");
    }

    if (navigator.deviceMemory !== undefined && navigator.deviceMemory < 2) {
      issues.push("sandbox: low device memory (possible sandbox/emulator)");
    }

    if (nav?.connection?.type === "none" && nav?.onLine === false) {
      // offline — not a compromise indicator
    }
  } catch {
    issues.push("error: compromise check failed");
  }

  return { isCompromised: issues.length > 0, issues };
}