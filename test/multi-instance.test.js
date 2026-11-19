'use strict'

const assert = require('node:assert')
const { test } = require('node:test')
const Fastify = require('fastify')
const fastifyCookie = require('@fastify/cookie')
const fastifySecureSession = require('@fastify/secure-session')
const proxyquire = require('proxyquire')
const sinon = require('sinon')
const fastifyCsrf = require('../')

const sodium = require('sodium-native')
const secureSessionKey = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES)
sodium.randombytes_buf(secureSessionKey)

async function buildTenant (registerOpts) {
  const fastify = Fastify()
  await fastify.register(fastifyCookie)
  await fastify.register(fastifyCsrf, registerOpts)

  fastify.post('/login', async (req, reply) => {
    const userInfo = reply.request.body?.username
    const token = reply.generateCsrf(userInfo ? { userInfo } : undefined)
    return { token }
  })

  fastify.post('/', { preHandler: fastify.csrfProtection }, async (req) => {
    return req.body
  })

  await fastify.ready()
  return fastify
}

async function login (fastify, username) {
  const response = await fastify.inject({
    method: 'POST',
    path: '/login',
    body: username ? { username } : {}
  })
  assert.strictEqual(response.statusCode, 200)
  return { cookie: response.cookies[0].value, token: response.json().token }
}

async function protectedRequest (fastify, cookie, token, body) {
  return fastify.inject({
    method: 'POST',
    path: '/',
    cookies: { _csrf: cookie },
    body: { _csrf: token, ...body }
  })
}

test('shared csrfOpts is not mutated across instances', async t => {
  const sharedCsrfOpts = { hmacKey: 'shared-hmac' }

  const tenantA = await buildTenant({
    getUserInfo: req => req.body.username,
    csrfOpts: sharedCsrfOpts
  })

  const tenantB = await buildTenant({ csrfOpts: sharedCsrfOpts })

  t.assert.deepStrictEqual(sharedCsrfOpts, { hmacKey: 'shared-hmac' })
  t.assert.ok(!('userInfo' in sharedCsrfOpts))

  const credentialsA = await login(tenantA, 'alice')
  const allowedA = await protectedRequest(tenantA, credentialsA.cookie, credentialsA.token, { username: 'alice' })
  t.assert.strictEqual(allowedA.statusCode, 200)

  const rejectedA = await protectedRequest(tenantA, credentialsA.cookie, credentialsA.token, { username: 'bob' })
  t.assert.strictEqual(rejectedA.statusCode, 403)

  const credentialsB = await login(tenantB)
  const allowedB = await protectedRequest(tenantB, credentialsB.cookie, credentialsB.token, {})
  t.assert.strictEqual(allowedB.statusCode, 200)

  await Promise.all([tenantA.close(), tenantB.close()])
})

test('each instance keeps its own hmacKey semantics', async t => {
  const tenantA = await buildTenant({
    getUserInfo: req => req.body.username,
    csrfOpts: { hmacKey: 'hmac-A' }
  })

  const tenantC = await buildTenant({
    getUserInfo: req => req.body.username,
    csrfOpts: { hmacKey: 'hmac-C' }
  })

  const credentialsA = await login(tenantA, 'alice')

  const crossTenant = await protectedRequest(tenantC, credentialsA.cookie, credentialsA.token, { username: 'alice' })
  t.assert.strictEqual(crossTenant.statusCode, 403)

  await Promise.all([tenantA.close(), tenantC.close()])
})

test('concurrent registrations on shared opts stay isolated', async t => {
  const sharedCsrfOpts = { hmacKey: 'shared-hmac' }

  const tenants = await Promise.all([
    buildTenant({ getUserInfo: req => req.body.username, csrfOpts: sharedCsrfOpts }),
    buildTenant({ csrfOpts: sharedCsrfOpts }),
    buildTenant({ getUserInfo: req => req.body.username, csrfOpts: sharedCsrfOpts }),
    buildTenant({ csrfOpts: null })
  ])

  t.assert.deepStrictEqual(sharedCsrfOpts, { hmacKey: 'shared-hmac' })

  const withUserInfo = await login(tenants[0], 'alice')
  t.assert.strictEqual(
    (await protectedRequest(tenants[0], withUserInfo.cookie, withUserInfo.token, { username: 'alice' })).statusCode,
    200
  )
  t.assert.strictEqual(
    (await protectedRequest(tenants[0], withUserInfo.cookie, withUserInfo.token, { username: 'mallory' })).statusCode,
    403
  )

  const withoutUserInfo = await login(tenants[1])
  t.assert.strictEqual(
    (await protectedRequest(tenants[1], withoutUserInfo.cookie, withoutUserInfo.token, {})).statusCode,
    200
  )

  const withUserInfoAgain = await login(tenants[2], 'alice')
  t.assert.strictEqual(
    (await protectedRequest(tenants[2], withUserInfoAgain.cookie, withUserInfoAgain.token, { username: 'alice' })).statusCode,
    200
  )

  const nullOptsTenant = await login(tenants[3])
  t.assert.strictEqual(
    (await protectedRequest(tenants[3], nullOptsTenant.cookie, nullOptsTenant.token, {})).statusCode,
    200
  )

  await Promise.all(tenants.map(tenant => tenant.close()))
})

test('every instance receives a distinct frozen csrf config', async t => {
  const csrf = sinon.stub()

  const proxiedFastifyCsrf = proxyquire('../', {
    '@fastify/csrf': function (...args) {
      return csrf(...args)
    }
  })

  const sharedCsrfOpts = { hmacKey: 'shared-hmac', saltLength: 10 }

  async function proxiedTenant (registerOpts) {
    const fastify = Fastify()
    await fastify.register(fastifyCookie)
    await fastify.register(proxiedFastifyCsrf, registerOpts)
    await fastify.ready()
    await fastify.close()
  }

  await Promise.all([
    proxiedTenant({ getUserInfo: () => 'alice', csrfOpts: sharedCsrfOpts }),
    proxiedTenant({ csrfOpts: sharedCsrfOpts }),
    proxiedTenant({}),
    proxiedTenant({ csrfOpts: { userInfo: true, hmacKey: 'hmac-D' } })
  ])

  t.assert.strictEqual(csrf.callCount, 4)

  const [withUserInfo, withoutUserInfo, defaults, inheritedUserInfo] = csrf.getCalls().map(call => call.args[0])

  t.assert.ok(Object.isFrozen(withUserInfo))
  t.assert.ok(Object.isFrozen(withoutUserInfo))
  t.assert.ok(Object.isFrozen(defaults))
  t.assert.ok(Object.isFrozen(inheritedUserInfo))

  t.assert.notStrictEqual(withUserInfo, sharedCsrfOpts)
  t.assert.notStrictEqual(withoutUserInfo, sharedCsrfOpts)
  t.assert.notStrictEqual(withUserInfo, withoutUserInfo)

  t.assert.deepStrictEqual(withUserInfo, { hmacKey: 'shared-hmac', saltLength: 10, userInfo: true })
  t.assert.deepStrictEqual(withoutUserInfo, { hmacKey: 'shared-hmac', saltLength: 10, userInfo: false })
  t.assert.deepStrictEqual(defaults, { userInfo: false })
  t.assert.deepStrictEqual(inheritedUserInfo, { userInfo: true, hmacKey: 'hmac-D' })

  t.assert.deepStrictEqual(sharedCsrfOpts, { hmacKey: 'shared-hmac', saltLength: 10 })
})

test('legacy single-instance defaults keep working', async t => {
  const fastify = Fastify()
  await fastify.register(fastifyCookie)
  await fastify.register(fastifyCsrf)

  fastify.get('/', async (_req, reply) => {
    return { token: reply.generateCsrf() }
  })

  fastify.post('/', { preHandler: fastify.csrfProtection }, async (req) => {
    return req.body
  })

  await fastify.ready()

  const response = await fastify.inject({ method: 'GET', path: '/' })
  t.assert.strictEqual(response.statusCode, 200)

  const verified = await fastify.inject({
    method: 'POST',
    path: '/',
    cookies: { _csrf: response.cookies[0].value },
    body: { _csrf: response.json().token }
  })
  t.assert.strictEqual(verified.statusCode, 200)

  await fastify.close()
})

test('secure-session userInfo flow does not mutate the shared csrfOpts', async t => {
  const sharedCsrfOpts = { userInfo: true, hmacKey: 'shared-hmac' }

  const fastify = Fastify()
  await fastify.register(fastifySecureSession, { key: secureSessionKey, cookie: { path: '/', secure: false } })
  await fastify.register(fastifyCsrf, {
    sessionPlugin: '@fastify/secure-session',
    getUserInfo (req) {
      return req.session.get('username')
    },
    csrfOpts: sharedCsrfOpts
  })

  fastify.post('/login', async (req, reply) => {
    req.session.set('username', req.body.username)
    return { token: reply.generateCsrf({ userInfo: req.body.username }) }
  })

  fastify.post('/', { preHandler: fastify.csrfProtection }, async (req) => {
    return req.body
  })

  await fastify.ready()

  t.assert.deepStrictEqual(sharedCsrfOpts, { userInfo: true, hmacKey: 'shared-hmac' })

  const loginResponse = await fastify.inject({
    method: 'POST',
    path: '/login',
    body: { username: 'alice' }
  })
  t.assert.strictEqual(loginResponse.statusCode, 200)

  const cookie = loginResponse.cookies[0]
  const { token } = loginResponse.json()

  const verified = await fastify.inject({
    method: 'POST',
    path: '/',
    cookies: { session: cookie.value },
    body: { _csrf: token, username: 'alice' }
  })
  t.assert.strictEqual(verified.statusCode, 200)

  t.assert.deepStrictEqual(sharedCsrfOpts, { hmacKey: 'shared-hmac', userInfo: true })

  await fastify.close()
})
