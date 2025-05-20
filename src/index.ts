import { Hono } from 'hono'
import { requestId } from 'hono/request-id'
import { logger } from 'hono/logger'

import { verify, hash } from '../wasm/pkg/argon2id_wasm'

// Type declarations
interface Argon2idOptions {
  time_cost: number
  memory_cost: number
  parallelism: number
  salt_length?: number
}

interface HashRequestBody {
  password: string
  options?: Partial<Argon2idOptions>
}

interface VerifyRequestBody {
  hash: string
  password: string
}

interface BatchHashRequestBody {
  passwords: string[]
  options?: Partial<Argon2idOptions>
}

interface BatchHashResult {
  hashes: string[]
  errors: Array<{ index: number; message: string }>
}

interface ConfigResponse {
  defaultOptions: Argon2idOptions
  limits: {
    time_cost: { min: number; max: number }
    memory_cost: { min: number; max: number; note: string }
    parallelism: { min: number; max: number }
    salt_length: { min: number; max: number }
    batch_size: { max: number }
  }
}

// Initialize Hono app with types
const app = new Hono()

// Middleware
app.use('*', requestId())
app.use('*', logger())

// Constants and configuration
const DEFAULT_OPTIONS: Argon2idOptions = {
  time_cost: 2,
  memory_cost: 19456,
  parallelism: 1,
  // Adding salt length for better security
  salt_length: 16,
}

// Validation functions
const validatePassword = (password: unknown): boolean => {
  if (!password || typeof password !== 'string') {
    throw new Error('Password must be a non-empty string')
  }
  return true
}

const validateHashOptions = (options?: Partial<Argon2idOptions>): Argon2idOptions => {
  if (!options || typeof options !== 'object') return { ...DEFAULT_OPTIONS }

  const validatedOptions: Argon2idOptions = { ...DEFAULT_OPTIONS }

  // Validate time_cost (between 1 and 10)
  if (
    Number.isInteger(options.time_cost) &&
    options.time_cost !== undefined &&
    options.time_cost >= 1 &&
    options.time_cost <= 10
  ) {
    validatedOptions.time_cost = options.time_cost
  }

  // Validate memory_cost (between 8192 and 1048576, and must be a power of 2)
  if (
    Number.isInteger(options.memory_cost) &&
    options.memory_cost !== undefined &&
    options.memory_cost >= 8192 &&
    options.memory_cost <= 1048576 &&
    (options.memory_cost & (options.memory_cost - 1)) === 0
  ) {
    validatedOptions.memory_cost = options.memory_cost
  }

  // Validate parallelism (between 1 and 16)
  if (
    Number.isInteger(options.parallelism) &&
    options.parallelism !== undefined &&
    options.parallelism >= 1 &&
    options.parallelism <= 16
  ) {
    validatedOptions.parallelism = options.parallelism
  }

  // Validate salt_length (between 8 and 32)
  if (
    Number.isInteger(options.salt_length) &&
    options.salt_length !== undefined &&
    options.salt_length >= 8 &&
    options.salt_length <= 32
  ) {
    validatedOptions.salt_length = options.salt_length
  }

  return validatedOptions
}

// API endpoints

/**
 * @route GET /
 * @description Returns an overview of the Argon2id Password Hashing API, including available endpoints and version information.
 * @returns {Object} API status, message, version, and list of endpoints
 * @example
 * Response:
 * {
 *   status: 'ok',
 *   message: 'Argon2id Password Hashing API',
 *   version: '1.0.0',
 *   endpoints: { ... }
 * }
 */
app.get('/', (c) => {
  return c.json({
    status: 'ok',
    message: 'Argon2id Password Hashing API',
    version: '1.0.0',
    endpoints: {
      '/': 'API overview (GET)',
      '/hash': 'Hash a password (POST)',
      '/verify': 'Verify a password against a hash (POST)',
      '/batch-hash': 'Hash multiple passwords (POST)',
      '/config': 'Get default configuration and limits (GET)',
      '/health': 'Service health check (GET)',
    },
  })
})

/**
 * @route POST /hash
 * @description Hashes a single password using the Argon2id algorithm with configurable options.
 * @param {HashRequestBody} body - Request body containing the password and optional Argon2id options
 * @body {string} password - The password to hash (required)
 * @body {Partial<Argon2idOptions>} [options] - Optional hashing parameters (time_cost, memory_cost, parallelism, salt_length)
 * @returns {Object} Object containing the generated hash
 * @throws {400} If password is invalid or options are malformed
 * @example
 * Request:
 * {
 *   password: "myPassword123",
 *   options: { time_cost: 3, memory_cost: 16384, parallelism: 2 }
 * }
 * Response:
 * {
 *   hash: "$argon2id$v=19$m=16384,t=3,p=2$..."
 * }
 */
app.post('/hash', async (c) => {
  try {
    const body = await c.req.json<HashRequestBody>()
    const { password, options } = body

    // Validate input
    validatePassword(password)
    const validatedOptions = validateHashOptions(options)

    // Perform hash operation
    const hashedPassword = hash(password, validatedOptions)
    return c.json({ hash: hashedPassword })
  } catch (error: any) {
    c.status(400)
    return c.json({ error: error.message || 'Bad request' })
  }
})

/**
 * @route POST /verify
 * @description Verifies a password against a provided Argon2id hash.
 * @param {VerifyRequestBody} body - Request body containing the hash and password
 * @body {string} hash - The Argon2id hash to verify against (required)
 * @body {string} password - The password to verify (required)
 * @returns {Object} Object indicating if the password matches the hash
 * @throws {400} If hash or password is invalid
 * @example
 * Request:
 * {
 *   hash: "$argon2id$v=19$m=19456,t=2,p=1$...",
 *   password: "myPassword123"
 * }
 * Response:
 * {
 *   isValid: true
 * }
 */
app.post('/verify', async (c) => {
  try {
    const body = await c.req.json<VerifyRequestBody>()
    const { hash: passwordHash, password } = body

    // Validate input
    if (!passwordHash || typeof passwordHash !== 'string') {
      c.status(400)
      return c.json({ error: 'Hash must be a non-empty string' })
    }
    validatePassword(password)

    // Perform verification
    const isValid = verify(passwordHash, password)
    return c.json({ isValid })
  } catch (error: any) {
    c.status(400)
    return c.json({ error: error.message || 'Bad request' })
  }
})

/**
 * @route POST /batch-hash
 * @description Hashes multiple passwords in a single request using the Argon2id algorithm.
 * @param {BatchHashRequestBody} body - Request body containing an array of passwords and optional Argon2id options
 * @body {string[]} passwords - Array of passwords to hash (required, max 100)
 * @body {Partial<Argon2idOptions>} [options] - Optional hashing parameters
 * @returns {BatchHashResult} Object containing an array of hashes and any errors encountered
 * @throws {400} If passwords array is invalid or exceeds batch size limit
 * @example
 * Request:
 * {
 *   passwords: ["pwd1", "pwd2"],
 *   options: { time_cost: 3 }
 * }
 * Response:
 * {
 *   hashes: ["$argon2id$v=19$...", "$argon2id$v=19$..."],
 *   errors: []
 * }
 */
app.post('/batch-hash', async (c) => {
  try {
    const body = await c.req.json<BatchHashRequestBody>()
    const { passwords, options } = body

    // Validate input
    if (!Array.isArray(passwords) || passwords.length === 0) {
      c.status(400)
      return c.json({ error: 'Passwords must be a non-empty array' })
    }

    if (passwords.length > 100) {
      c.status(400)
      return c.json({ error: 'Batch size limited to 100 passwords' })
    }

    const validatedOptions = validateHashOptions(options)

    // Process each password with proper error handling
    const results: BatchHashResult = {
      hashes: [],
      errors: [],
    }

    passwords.forEach((pwd, index) => {
      try {
        validatePassword(pwd)
        results.hashes.push(hash(pwd, validatedOptions))
      } catch (error: any) {
        results.errors.push({ index, message: error.message })
      }
    })

    return c.json(results)
  } catch (error: any) {
    c.status(400)
    return c.json({ error: error.message || 'Bad request' })
  }
})

/**
 * @route GET /config
 * @description Returns the default Argon2id configuration and parameter limits.
 * @returns {ConfigResponse} Object containing default options and allowed parameter ranges
 * @example
 * Response:
 * {
 *   defaultOptions: {
 *     time_cost: 2,
 *     memory_cost: 19456,
 *     parallelism: 1,
 *     salt_length: 16
 *   },
 *   limits: { ... }
 * }
 */
app.get('/config', (c) => {
  const config: ConfigResponse = {
    defaultOptions: DEFAULT_OPTIONS,
    limits: {
      time_cost: { min: 1, max: 10 },
      memory_cost: { min: 8192, max: 1048576, note: 'Must be a power of 2' },
      parallelism: { min: 1, max: 16 },
      salt_length: { min: 8, max: 32 },
      batch_size: { max: 100 },
    },
  }
  return c.json(config)
})

/**
 * @route GET /health
 * @description Performs a health check of the API service.
 * @returns {Object} Object indicating the service status
 * @example
 * Response:
 * {
 *   status: 'ok'
 * }
 */
app.get('/health', (c) => c.json({ status: 'ok' }))

// Error handling middleware
app.onError((err, c) => {
  console.error(`[Error] ${err.message}`)
  c.status(500)
  return c.json({
    error: 'Internal server error',
    message: err.message,
  })
})

export default app
