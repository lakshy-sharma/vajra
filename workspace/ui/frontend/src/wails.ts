// src/wails.ts
//
// Re-exports the auto-generated Wails bindings from wailsjs/.
// wailsjs/ is produced by `wails dev` or `wails build` — never edit it manually.
//
// All imports in the app should go through this file so that:
//   a) the wailsjs/ path appears in exactly one place, and
//   b) it's easy to swap in a mock during unit tests.

// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore — wailsjs/ does not exist until `wails dev` generates it.
export * from '../wailsjs/go/main/App'
