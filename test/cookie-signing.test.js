'use strict'

const { test } = require('node:test')
const Fastify = require('fastify')
const fastifyCookie = require('@fastify/cookie')
const CSRF = require('@fastify/csrf')
const fastifyCsrf = require('../')

async function buildApp (cookieSecret = 'supersecret', csrfOpts = {}) {
  const fastify = Fastify()
  fastify.register(fastifyCookie, { secret: cookieSecret })
  fastify.register(fastifyCsrf, { cookieOpts: { signed: true }, ...csrfOpts })
  fastify.register(async function routes (instance) {
    instance.get('/', async (_req, reply) => {
      return { token: reply.generateCsrf() }
    })

    instance.post('/', { onRequest: instance.csrfProtection }, async (req) => {
      return req.body
    })
  })

  await fastify.ready()
  return fastify
}

test('cookie mode refuses to start without signed cookies by default', async t => {
  const fastify = Fastify()
  fastify.register(fastifyCookie)
  fastify.register(fastifyCsrf)

  await t.assert.rejects(fastify.ready(), (err) => {
    t.assert.strictEqual(err.message.includes('signed cookies'), true)
    return true
  })
})

test('cookie mode starts when allowUnsignedCookie is explicitly enabled', async t => {
  const fastify = Fastify()
  fastify.register(fastifyCookie)
  fastify.register(fastifyCsrf, { allowUnsignedCookie: true })

  await t.assert.doesNotReject(fastify.ready())
})

test('allowUnsignedCookie must be a boolean', async t => {
  const fastify = Fastify()
  fastify.register(fastifyCookie)
  fastify.register(fastifyCsrf, { allowUnsignedCookie: 'yes' })

  await t.assert.rejects(fastify.ready(), (err) => {
    t.assert.strictEqual(err.message, 'allowUnsignedCookie should be a boolean')
    return true
  })
})

test('session plugins do not require signed cookies', async t => {
  const fastify = Fastify()
  fastify.register(fastifyCookie)
  fastify.register(fastifyCsrf, { sessionPlugin: '@fastify/session' })

  await t.assert.doesNotReject(fastify.ready())
})

test('rejects a tampered unsigned _csrf cookie sent to a signed deployment', async t => {
  const fastify = await buildApp()

  const response = await fastify.inject({
    method: 'GET',
    path: '/'
  })
  const token = response.json().token

  // Subdomain cookie tossing: attacker overwrites _csrf with a self-chosen value
  // and mints a matching double-submit token from the same value.
  const attackerSecret = new CSRF().secretSync()
  const attackerToken = new CSRF().create(attackerSecret)

  const forged = await fastify.inject({
    method: 'POST',
    path: '/',
    payload: { hello: 'world' },
    headers: { 'csrf-token': attackerToken },
    cookies: { _csrf: 'attacker-controlled-secret' }
  })

  t.assert.strictEqual(forged.statusCode, 403)
  t.assert.strictEqual(forged.json().message, 'Missing csrf secret')

  const tossed = await fastify.inject({
    method: 'POST',
    path: '/',
    payload: { hello: 'world' },
    headers: { 'csrf-token': attackerToken },
    cookies: { _csrf: attackerSecret }
  })

  t.assert.strictEqual(tossed.statusCode, 403)
  t.assert.strictEqual(tossed.json().message, 'Missing csrf secret')

  const legit = await fastify.inject({
    method: 'POST',
    path: '/',
    payload: { hello: 'world' },
    headers: { 'csrf-token': token },
    cookies: { _csrf: response.cookies[0].value }
  })

  t.assert.strictEqual(legit.statusCode, 200)
})

test('rejects a cookie signed with an untrusted secret', async t => {
  const victim = await buildApp()

  const attacker = Fastify()
  attacker.register(fastifyCookie, { secret: 'attacker-secret' })
  attacker.register(fastifyCsrf, {
    cookieOpts: { signed: true },
    allowUnsignedCookie: false
  })
  attacker.register(async function routes (instance) {
    instance.get('/', async (_req, reply) => {
      return { token: reply.generateCsrf() }
    })
  })

  const forgedResponse = await attacker.inject({ method: 'GET', path: '/' })
  const forgedCookie = forgedResponse.cookies[0].value
  const forgedToken = forgedResponse.json().token

  const response = await victim.inject({
    method: 'POST',
    path: '/',
    payload: { hello: 'world' },
    headers: { 'csrf-token': forgedToken },
    cookies: { _csrf: forgedCookie }
  })

  t.assert.strictEqual(response.statusCode, 403)
  t.assert.strictEqual(response.json().message, 'Missing csrf secret')
})

test('does not fall back to the raw unsigned value when verification fails', async t => {
  const fastify = await buildApp()

  const response = await fastify.inject({ method: 'GET', path: '/' })
  const { token } = response.json()

  const unsignedCookie = response.cookies[0].value.split('.')[0]

  const replayed = await fastify.inject({
    method: 'POST',
    path: '/',
    payload: { hello: 'world' },
    headers: { 'csrf-token': token },
    cookies: { _csrf: unsignedCookie }
  })

  t.assert.strictEqual(replayed.statusCode, 403)
  t.assert.strictEqual(replayed.json().message, 'Missing csrf secret')
})

test('secret rotation keeps accepting cookies signed with an old secret', async t => {
  const oldApp = Fastify()
  oldApp.register(fastifyCookie, { secret: 'old-secret' })
  oldApp.register(fastifyCsrf, { cookieOpts: { signed: true } })
  oldApp.register(async function routes (instance) {
    instance.get('/', async (_req, reply) => ({ token: reply.generateCsrf() }))
  })

  const oldResponse = await oldApp.inject({ method: 'GET', path: '/' })
  const oldCookie = oldResponse.cookies[0].value
  const oldToken = oldResponse.json().token

  const rotatedApp = Fastify()
  rotatedApp.register(fastifyCookie, { secret: ['new-secret', 'old-secret'] })
  rotatedApp.register(fastifyCsrf, { cookieOpts: { signed: true } })
  rotatedApp.register(async function routes (instance) {
    instance.post('/', { onRequest: instance.csrfProtection }, async (req) => req.body)
  })

  const rotatedResponse = await rotatedApp.inject({
    method: 'POST',
    path: '/',
    payload: { hello: 'world' },
    headers: { 'csrf-token': oldToken },
    cookies: { _csrf: oldCookie }
  })

  t.assert.strictEqual(rotatedResponse.statusCode, 200)
  t.assert.strictEqual(rotatedResponse.json().hello, 'world')
})

test('generateCsrf ignores cookies that fail signature verification and rotates the secret', async t => {
  const fastify = await buildApp()

  const response = await fastify.inject({
    method: 'GET',
    path: '/',
    cookies: { _csrf: 'forged.value' }
  })

  t.assert.strictEqual(response.statusCode, 200)
  const renewedCookie = response.cookies[0]
  t.assert.ok(renewedCookie)
  t.assert.notStrictEqual(renewedCookie.value, 'forged.value')
})
