import { Hono } from 'hono'

import { verify, hash } from '../wasm/pkg/argon2id_wasm'

const app = new Hono()

app.get('/', async c => {
  const options = {
    time_cost: 2,
    memory_cost: 19456,
    parallelism: 1,
  }
  const plain = 'plain'
  const password = hash(plain, options)

  const verifyed = verify(password , plain)

  return c.json({ password, verifyed })
})

export default app
