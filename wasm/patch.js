/*
* Patch for Cloudflare Workers Rust WASM module
* URL: https://developers.cloudflare.com/workers/languages/rust/
*/

import * as imports from './argon2id_wasm_bg.js'

import wkmod from './argon2id_wasm_bg.wasm'
import * as nodemod from './argon2id_wasm_bg.wasm'
if (typeof process !== 'undefined' && process.release.name === 'node') {
  imports.__wbg_set_wasm(nodemod)
} else {
  const instance = new WebAssembly.Instance(wkmod, {
    './argon2id_wasm_bg.js': imports,
  })
  imports.__wbg_set_wasm(instance.exports)
}

export * from './argon2id_wasm_bg.js'
