'use strict'

const { test } = require('node:test')
const Fastify = require('fastify')
const fastifyCookie = require('@fastify/cookie')
const fastifySession = require('@fastify/session')
const fastifySecureSession = require('@fastify/secure-session')
const fastifyCsrf = require('../')

const sodium = require('sodium-native')
const key = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES)
sodium.randombytes_buf(key)

const sessionKey = '_csrf'
const prototypeSecret = 'inherited-secret-from-the-prototype'

function resetPrototype () {
  if (Object.hasOwn(Object.prototype, sessionKey)) {
    delete Object.prototype[sessionKey]
  }
}

function build (sessionPlugin) {
  const fastify = Fastify()
  fastify.register(fastifyCookie)
  if (sessionPlugin === '@fastify/session') {
    fastify.register(fastifySession, {
      secret: 'a'.repeat(32),
      cookie: { path: '/', secure: false }
    })
  } else if (sessionPlugin === '@fastify/secure-session') {
    fastify.register(fastifySecureSession, { key, cookie: { path: '/', secure: false } })
  }
  fastify.register(fastifyCsrf, sessionPlugin ? { sessionPlugin } : {})

  fastify.get('/generate', async (_req, reply) => {
    return { token: reply.generateCsrf() }
  })

  fastify.after(() => {
    fastify.post('/protected', { preValidation: fastify.csrfProtection }, async (req) => {
      return req.body
    })
  })

  return fastify
}

async function withPollutedPrototype (run) {
  // eslint-disable-next-line no-extend-native
  Object.prototype[sessionKey] = prototypeSecret
  try {
    await run()
  } finally {
    resetPrototype()
  }
}

test('first generation creates a valid secret for every session plugin', async t => {
  const plugins = ['@fastify/cookie', '@fastify/session', '@fastify/secure-session']

  for (const sessionPlugin of plugins) {
    await t.test(sessionPlugin, async t => {
      const fastify = await build(sessionPlugin)

      const response = await fastify.inject({ method: 'GET', path: '/generate' })
      t.assert.strictEqual(response.statusCode, 200)
      t.assert.strictEqual(typeof response.json().token, 'string')
      t.assert.strictEqual(response.cookies.length > 0, true)

      await fastify.close()
    })
  }
})

test('normal rotation keeps working after a valid secret is stored', async t => {
  const plugins = ['@fastify/cookie', '@fastify/session', '@fastify/secure-session']

  for (const sessionPlugin of plugins) {
    await t.test(sessionPlugin, async t => {
      const fastify = await build(sessionPlugin)

      const firstResponse = await fastify.inject({ method: 'GET', path: '/generate' })
      t.assert.strictEqual(firstResponse.statusCode, 200)
      const firstToken = firstResponse.json().token
      const cookies = Object.fromEntries(
        firstResponse.cookies.map(cookie => [cookie.name, cookie.value])
      )

      const secondResponse = await fastify.inject({
        method: 'GET',
        path: '/generate',
        cookies
      })
      t.assert.strictEqual(secondResponse.statusCode, 200)
      t.assert.notStrictEqual(secondResponse.json().token, firstToken)
      Object.assign(cookies, Object.fromEntries(
        secondResponse.cookies.map(cookie => [cookie.name, cookie.value])
      ))

      const protectedResponse = await fastify.inject({
        method: 'POST',
        path: '/protected',
        payload: { hello: 'world', _csrf: secondResponse.json().token },
        cookies
      })
      t.assert.strictEqual(protectedResponse.statusCode, 200)
      t.assert.strictEqual(protectedResponse.json().hello, 'world')

      await fastify.close()
    })
  }
})

test('@fastify/session: non-string and malformed secrets explicitly fail', async t => {
  const badSecrets = [
    ['array', ['not', 'a', 'string']],
    ['object', { not: 'a string' }],
    ['number', 42],
    ['boolean', true],
    ['short string', 'short'],
    ['long string', 'x'.repeat(257)]
  ]

  for (const [label, badSecret] of badSecrets) {
    await t.test(label, async t => {
      const fastify = Fastify()
      await fastify.register(fastifyCookie)
      await fastify.register(fastifySession, {
        secret: 'a'.repeat(32),
        cookie: { path: '/', secure: false }
      })
      await fastify.register(fastifyCsrf, { sessionPlugin: '@fastify/session' })

      fastify.get('/pollute', async (req) => {
        req.session[sessionKey] = badSecret
        return {}
      })
      fastify.get('/generate', async (_req, reply) => reply.generateCsrf())
      fastify.post('/protected', { onRequest: fastify.csrfProtection }, async () => 'ok')

      await fastify.ready()

      const polluteResponse = await fastify.inject({ method: 'GET', path: '/pollute' })
      t.assert.strictEqual(polluteResponse.statusCode, 200)
      const sessionCookie = polluteResponse.cookies[0]
      const sessionCookies = { [sessionCookie.name]: sessionCookie.value }

      const generateResponse = await fastify.inject({
        method: 'GET',
        path: '/generate',
        cookies: sessionCookies
      })
      t.assert.strictEqual(generateResponse.statusCode, 403)
      t.assert.strictEqual(generateResponse.json().message, 'Invalid csrf secret')

      const protectedResponse = await fastify.inject({
        method: 'POST',
        path: '/protected',
        payload: {},
        cookies: sessionCookies
      })
      t.assert.strictEqual(protectedResponse.statusCode, 403)
      t.assert.strictEqual(protectedResponse.json().message, 'Invalid csrf secret')

      await fastify.close()
    })
  }

  await t.test('empty string is treated as missing', async t => {
    const fastify = await build('@fastify/session')

    const response = await fastify.inject({
      method: 'POST',
      path: '/protected',
      payload: { hello: 'world' }
    })

    t.assert.strictEqual(response.statusCode, 403)
    t.assert.strictEqual(response.json().message, 'Missing csrf secret')

    await fastify.close()
  })
})

test('@fastify/cookie: malformed cookie secrets explicitly fail', async t => {
  const badSecrets = [
    ['short string', 'short'],
    ['long string', 'x'.repeat(257)]
  ]

  for (const [label, badSecret] of badSecrets) {
    await t.test(label, async t => {
      const fastify = await build('@fastify/cookie')
      const cookies = { [sessionKey]: badSecret }

      const generateResponse = await fastify.inject({
        method: 'GET',
        path: '/generate',
        cookies
      })
      t.assert.strictEqual(generateResponse.statusCode, 403)
      t.assert.strictEqual(generateResponse.json().message, 'Invalid csrf secret')

      const protectedResponse = await fastify.inject({
        method: 'POST',
        path: '/protected',
        payload: {},
        cookies
      })
      t.assert.strictEqual(protectedResponse.statusCode, 403)
      t.assert.strictEqual(protectedResponse.json().message, 'Invalid csrf secret')

      await fastify.close()
    })
  }
})

test('@fastify/secure-session: malformed stored secret explicitly fails', async t => {
  const badSecrets = [
    ['array', ['not', 'a', 'string']],
    ['object', { not: 'a string' }],
    ['short string', 'short']
  ]

  for (const [label, badSecret] of badSecrets) {
    await t.test(label, async t => {
      const fastify = Fastify()
      await fastify.register(fastifyCookie)
      await fastify.register(fastifySecureSession, { key, cookie: { path: '/', secure: false } })
      await fastify.register(fastifyCsrf, { sessionPlugin: '@fastify/secure-session' })

      fastify.get('/pollute', async (req) => {
        req.session.set(sessionKey, badSecret)
        return {}
      })
      fastify.get('/generate', async (_req, reply) => reply.generateCsrf())
      fastify.after(() => {
        fastify.post('/protected', { preValidation: fastify.csrfProtection }, async () => 'ok')
      })

      await fastify.ready()

      const polluteResponse = await fastify.inject({ method: 'GET', path: '/pollute' })
      t.assert.strictEqual(polluteResponse.statusCode, 200)
      const sessionCookie = polluteResponse.cookies[0]
      const sessionCookies = { [sessionCookie.name]: sessionCookie.value }

      const generateResponse = await fastify.inject({
        method: 'GET',
        path: '/generate',
        cookies: sessionCookies
      })
      t.assert.strictEqual(generateResponse.statusCode, 403)
      t.assert.strictEqual(generateResponse.json().message, 'Invalid csrf secret')

      const protectedResponse = await fastify.inject({
        method: 'POST',
        path: '/protected',
        payload: {},
        cookies: sessionCookies
      })
      t.assert.strictEqual(protectedResponse.statusCode, 403)
      t.assert.strictEqual(protectedResponse.json().message, 'Invalid csrf secret')

      await fastify.close()
    })
  }
})

test('prototype pollution: inherited session secret is rejected', async t => {
  const plugins = ['@fastify/session', '@fastify/secure-session']

  await withPollutedPrototype(async () => {
    for (const sessionPlugin of plugins) {
      await t.test(sessionPlugin, async t => {
        const fastify = await build(sessionPlugin)

        const response = await fastify.inject({
          method: 'POST',
          path: '/protected',
          payload: { hello: 'world' }
        })

        t.assert.strictEqual(response.statusCode, 403)
        t.assert.strictEqual(response.json().message, 'Missing csrf secret')

        const generated = await fastify.inject({ method: 'GET', path: '/generate' })
        t.assert.strictEqual(generated.statusCode, 200)

        await fastify.close()
      })
    }
  })
})

test('prototype pollution: inherited secret never backs token verification', async t => {
  const plugins = ['@fastify/session', '@fastify/secure-session']

  await withPollutedPrototype(async () => {
    for (const sessionPlugin of plugins) {
      await t.test(sessionPlugin, async t => {
        const fastify = await build(sessionPlugin)

        const getResponse = await fastify.inject({ method: 'GET', path: '/generate' })
        t.assert.strictEqual(getResponse.statusCode, 200)
        const { token } = getResponse.json()
        const cookies = Object.fromEntries(
          getResponse.cookies.map(cookie => [cookie.name, cookie.value])
        )

        const protectedResponse = await fastify.inject({
          method: 'POST',
          path: '/protected',
          payload: { hello: 'world', _csrf: token },
          cookies
        })

        t.assert.strictEqual(protectedResponse.statusCode, 200)
        t.assert.strictEqual(protectedResponse.json().hello, 'world')

        await fastify.close()
      })
    }
  })
})
