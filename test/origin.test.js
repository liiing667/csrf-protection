'use strict'

const { test } = require('node:test')
const Fastify = require('fastify')
const fastifyCookie = require('@fastify/cookie')
const fastifyCsrf = require('../')

async function load (fastifyOpts, pluginOpts) {
  const fastify = Fastify(fastifyOpts)
  await fastify.register(fastifyCookie)
  await fastify.register(fastifyCsrf, pluginOpts)
  fastify.get('/', async (_req, reply) => {
    const token = reply.generateCsrf()
    return { token }
  })
  fastify.post('/', { onRequest: fastify.csrfProtection }, async () => {
    return { ok: true }
  })
  await fastify.ready()
  return fastify
}

async function postWithOrigin (fastify, headers = {}) {
  const tokenResponse = await fastify.inject({ method: 'GET', path: '/', headers })
  const cookie = tokenResponse.cookies[0]
  const token = tokenResponse.json().token
  return fastify.inject({
    method: 'POST',
    path: '/',
    headers: { ...headers, 'csrf-token': token },
    cookies: { [cookie.name]: cookie.value }
  })
}

test('verifyOrigin must be a boolean', async t => {
  t.plan(1)
  try {
    const fastify = Fastify()
    await fastify.register(fastifyCookie)
    await fastify.register(fastifyCsrf, { verifyOrigin: 'yes' })
    await fastify.ready()
  } catch (err) {
    t.assert.strictEqual(err.message, 'verifyOrigin should be a boolean')
  }
})

test('origin is not checked by default', async t => {
  t.plan(1)
  const fastify = await load({}, {})
  const response = await postWithOrigin(fastify, { origin: 'https://evil.com' })
  t.assert.strictEqual(response.statusCode, 200)
})

test('direct deployment', async t => {
  const fastify = await load({}, { verifyOrigin: true })

  await t.test('matching origin is accepted', async t => {
    t.plan(1)
    // light-my-request defaults to Host: localhost:80
    const response = await postWithOrigin(fastify, { origin: 'http://localhost' })
    t.assert.strictEqual(response.statusCode, 200)
  })

  await t.test('explicit default port is normalized', async t => {
    t.plan(1)
    const response = await postWithOrigin(fastify, { origin: 'http://localhost:80' })
    t.assert.strictEqual(response.statusCode, 200)
  })

  await t.test('host header default port is normalized', async t => {
    t.plan(1)
    const response = await postWithOrigin(fastify, { host: 'example.com:80', origin: 'http://example.com' })
    t.assert.strictEqual(response.statusCode, 200)
  })

  await t.test('missing origin header is accepted', async t => {
    t.plan(1)
    const response = await postWithOrigin(fastify)
    t.assert.strictEqual(response.statusCode, 200)
  })

  await t.test('different protocol is rejected', async t => {
    t.plan(1)
    const response = await postWithOrigin(fastify, { origin: 'https://localhost' })
    t.assert.strictEqual(response.statusCode, 403)
  })

  await t.test('different port is rejected', async t => {
    t.plan(1)
    const response = await postWithOrigin(fastify, { origin: 'http://localhost:8080' })
    t.assert.strictEqual(response.statusCode, 403)
  })

  await t.test('different host is rejected', async t => {
    t.plan(1)
    const response = await postWithOrigin(fastify, { origin: 'http://evil.com' })
    t.assert.strictEqual(response.statusCode, 403)
  })

  await t.test('malformed origin is rejected', async t => {
    t.plan(1)
    const response = await postWithOrigin(fastify, { origin: 'null' })
    t.assert.strictEqual(response.statusCode, 403)
  })

  await t.test('unparseable host header is rejected', async t => {
    t.plan(1)
    const response = await postWithOrigin(fastify, { host: '[::1', origin: 'http://localhost' })
    t.assert.strictEqual(response.statusCode, 403)
  })

  await t.test('failure response is stable', async t => {
    t.plan(2)
    const response = await postWithOrigin(fastify, { origin: 'http://evil.com' })
    t.assert.strictEqual(response.statusCode, 403)
    t.assert.deepStrictEqual(response.json(), {
      statusCode: 403,
      code: 'FST_CSRF_INVALID_ORIGIN',
      error: 'Forbidden',
      message: 'Invalid csrf origin'
    })
  })
})

test('trusted proxy', async t => {
  const fastify = await load({ trustProxy: true }, { verifyOrigin: true })
  const forwarded = { 'x-forwarded-proto': 'https', 'x-forwarded-host': 'example.com' }

  await t.test('origin matching the forwarded host is accepted', async t => {
    t.plan(1)
    const response = await postWithOrigin(fastify, { ...forwarded, origin: 'https://example.com' })
    t.assert.strictEqual(response.statusCode, 200)
  })

  await t.test('origin default port is normalized against the forwarded host', async t => {
    t.plan(1)
    const response = await postWithOrigin(fastify, { ...forwarded, origin: 'https://example.com:443' })
    t.assert.strictEqual(response.statusCode, 200)
  })

  await t.test('proxy port change on the forwarded host is normalized', async t => {
    t.plan(1)
    const headers = { 'x-forwarded-proto': 'https', 'x-forwarded-host': 'example.com:443', origin: 'https://example.com' }
    const response = await postWithOrigin(fastify, headers)
    t.assert.strictEqual(response.statusCode, 200)
  })

  await t.test('downgraded protocol is rejected', async t => {
    t.plan(1)
    const response = await postWithOrigin(fastify, { ...forwarded, origin: 'http://example.com' })
    t.assert.strictEqual(response.statusCode, 403)
  })

  await t.test('forged origin port is rejected', async t => {
    t.plan(1)
    const response = await postWithOrigin(fastify, { ...forwarded, origin: 'https://example.com:4443' })
    t.assert.strictEqual(response.statusCode, 403)
  })

  await t.test('forged origin host is rejected', async t => {
    t.plan(1)
    const response = await postWithOrigin(fastify, { ...forwarded, origin: 'https://evil.com' })
    t.assert.strictEqual(response.statusCode, 403)
  })
})

test('forwarded headers are ignored without trustProxy', async t => {
  const fastify = await load({}, { verifyOrigin: true })
  const forwarded = { 'x-forwarded-proto': 'https', 'x-forwarded-host': 'example.com' }

  await t.test('origin matching only the forwarded host is rejected', async t => {
    t.plan(1)
    const response = await postWithOrigin(fastify, { ...forwarded, origin: 'https://example.com' })
    t.assert.strictEqual(response.statusCode, 403)
  })

  await t.test('origin matching the direct host is accepted', async t => {
    t.plan(1)
    const response = await postWithOrigin(fastify, { ...forwarded, origin: 'http://localhost' })
    t.assert.strictEqual(response.statusCode, 200)
  })
})
