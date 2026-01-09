# SmartSecureKeypad

A lightweight, **SwiftUI-first secure numeric keypad** built as a Swift Package (SPM).  
`SmartSecureKeypad` provides a **fixed 3×4 numpad**, a **PIN indicator**, and **opt-in shuffle support** — while keeping UI rendering **fully customizable from the host app**.

> ✅ You build the UI.  
> ✅ The framework handles input buffering (digit/delete), completion, and optional digit shuffling.  
> ✅ Designed to integrate cleanly with real-world apps.

---

## Features

- **3×4 fixed layout** numeric keypad (0–9)
- **Custom key rendering** via `keyRenderer` (most useful in production)
- Built-in keys:
  - `.digit(Int)` — 0 ~ 9
  - `.delete` — backspace
  - `.shuffle` — rearrange/shuffle digit positions (optional)
  - `.empty` — spacer to keep layout fixed
- Input handling built-in:
  - Buffers PIN input (`pin` binding)
  - Handles delete
  - Calls `onComplete` when `pin.count == maxLength`
- Accessibility-friendly labels per key
- PIN progress indicator:
  - Default dot style
  - Supports **dash style** for empty slots (for “●●●— — —” style UIs)
- Opt-in lockout helpers (UI utility):
  - Remaining time formatter (`mm:ss`)
  - Lockout message view (`TimelineView`-based)

---

## Requirements

- iOS 16+
- SwiftUI

---

## Installation (Swift Package Manager)

### Xcode
1. `File` → `Add Packages…`
2. Add this repository URL
3. Select the `SmartSecureKeypad` product

### Package.swift
```swift
dependencies: [
  .package(url: "YOUR_REPO_URL_HERE", from: "0.1.0")
]
