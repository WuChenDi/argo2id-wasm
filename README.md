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

## API Endpoints

The API provides the following endpoints, implemented in `src/index.ts`. All endpoints are documented with JSDoc comments for clarity.

| Method | Endpoint        | Description                                      |
|--------|-----------------|--------------------------------------------------|
| GET    | `/`             | Returns API overview and available endpoints     |
| POST   | `/hash`         | Hashes a single password using Argon2id          |
| POST   | `/verify`       | Verifies a password against an Argon2id hash      |
| POST   | `/batch-hash`   | Hashes multiple passwords in a single request     |
| GET    | `/config`       | Returns default Argon2id options and limits       |
| GET    | `/health`       | Checks the health status of the API service       |

### Example Usage

1. **Hash a Password**:
   ```bash
   curl -X POST http://localhost:8787/hash \
     -H "Content-Type: application/json" \
     -d '{"password": "myPassword123", "options": {"time_cost": 3, "memory_cost": 16384, "parallelism": 2}}'
   ```
   Response:
   ```json
   {
     "hash": "$argon2id$v=19$m=16384,t=3,p=2$..."
   }
   ```

2. **Verify a Password**:
   ```bash
   curl -X POST http://localhost:8787/verify \
     -H "Content-Type: application/json" \
     -d '{"hash": "$argon2id$v=19$m=19456,t=2,p=1$...", "password": "myPassword123"}'
   ```
   Response:
   ```json
   {
     "isValid": true
   }
   ```

3. **Get Configuration**:
   ```bash
   curl http://localhost:8787/config
   ```
   Response:
   ```json
   {
     "defaultOptions": {
       "time_cost": 2,
       "memory_cost": 19456,
       "parallelism": 1,
       "salt_length": 16
     },
     "limits": {
       "time_cost": { "min": 1, "max": 10 },
       "memory_cost": { "min": 8192, "max": 1048576, "note": "Must be a power of 2" },
       "parallelism": { "min": 1, "max": 16 },
       "salt_length": { "min": 8, "max": 32 },
       "batch_size": { "max": 100 }
     }
   }
   ```

For detailed request/response formats, refer to the JSDoc comments in `src/index.ts`.

## Configuration

The API uses the following default Argon2id parameters, configurable via the `/hash` and `/batch-hash` endpoints:

- **time_cost**: 2 (number of iterations)
- **memory_cost**: 19456 KiB (approximately 19 MiB)
- **parallelism**: 1 (number of parallel threads)
- **salt_length**: 16 bytes

Parameter limits are enforced to ensure security and performance:
- `time_cost`: 1–10
- `memory_cost`: 8192–1048576 KiB (must be a power of 2)
- `parallelism`: 1–16
- `salt_length`: 8–32 bytes
- `batch_size`: Maximum 100 passwords per request

## Security Considerations

- **Argon2id**: Chosen for its resistance to brute-force, GPU, and side-channel attacks. It balances memory-hard and compute-hard properties.
- **Salt Length**: Defaults to 16 bytes for sufficient randomness, configurable between 8 and 32 bytes.
- **Input Validation**: All inputs are validated to prevent invalid or malicious requests.
- **Error Handling**: Comprehensive error responses ensure clear feedback for invalid inputs without exposing sensitive information.
- **Cloudflare Workers**: Runs in a secure, sandboxed environment with automatic scaling and global distribution.

Please include tests and update documentation as needed.

## Thanks

- [argon2-cloudflare](https://github.com/glotlabs/argon2-cloudflare)

## License

[MIT](https://choosealicense.com/licenses/mit/)
