# Argon2id WASM Demo in Cloudflare Workers

This project demonstrates how to use a WebAssembly (WASM) module to generate Argon2id hashes within a Cloudflare Workers environment. It showcases the integration of a Rust-compiled WASM module into a Cloudflare Worker, enabling high-performance password hashing functionality.

## Quick Start

1. Clone the repository: `git clone https://github.com/zzci/argo2id-wasm.git`
2. Install dependencies: `pnpm install`
3. Install Rust: `https://www.rust-lang.org/tools/install`
4. Install wasm-pack: `cargo install wasm-pack`
5. Build the Rust code to WASM: `pnpm run wasm`
6. Deploy the worker: `pnpm run dev`

## Project Structure

- `wasm/`: Rust source code and WASM-related files
- `src/`: Cloudflare Worker JavaScript code

## Thanks

- [argon2-cloudflare](https://github.com/glotlabs/argon2-cloudflare)

## License

[MIT](https://choosealicense.com/licenses/mit/)
