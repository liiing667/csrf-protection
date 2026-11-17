'use strict'

const { test } = require('node:test')
const Fastify = require('fastify')
const fastifyCookie = require('@fastify/cookie')
const sinon = require('sinon')
const fastifyCsrf = require('../')

async function buildApp (routePolicies, routes) {
  const fastify = Fastify()
  await fastify.register(fastifyCookie)
  await fastify.register(fastifyCsrf, { routePolicies })

  fastify.get('/token', async (_req, reply) => {
    return { token: reply.generateCsrf() }
  })

  routes(fastify)
  await fastify.ready()
  return fastify
}

function defaultRoutes (fastify) {
  fastify.post('/login', async () => ({ ok: 'login' }))
  fastify.post('/refresh', async () => ({ ok: 'refresh' }))
  fastify.route({
    method: ['PUT', 'PATCH'],
    url: '/settings',
    handler: async () => ({ ok: 'settings' })
  })
  fastify.post('/webhooks/:provider', async () => ({ ok: 'webhook' }))
  fastify.post('/users/:id', async () => ({ ok: 'user' }))
}

function defaultPolicies () {
  return [
    { url: '/webhooks/:provider', method: 'POST', policy: 'exempt', reason: 'public third-party webhook verified by signature' },
    { url: '/refresh', method: 'POST', policy: 'require' },
    { url: '/settings', method: ['PUT', 'PATCH'], policy: 'require' }
  ]
}

test('route policies: default still protects every state-changing route', async t => {
  const fastify = await buildApp(defaultPolicies(), defaultRoutes)

  await t.test('route without a policy requires a csrf token', async () => {
    const response = await fastify.inject({ method: 'POST', url: '/login' })
    t.assert.strictEqual(response.statusCode, 403)
    t.assert.strictEqual(response.json().message, 'Missing csrf secret')
  })

  await t.test('a require policy blocks a request without a token', async () => {
    const response = await fastify.inject({ method: 'POST', url: '/refresh' })
    t.assert.strictEqual(response.statusCode, 403)
    t.assert.strictEqual(response.json().message, 'Missing csrf secret')
  })

  await t.test('a require policy accepts a valid token', async () => {
    const tokenResponse = await fastify.inject({ method: 'GET', url: '/token' })
    const cookie = tokenResponse.cookies[0]
    const token = tokenResponse.json().token

    const response = await fastify.inject({
      method: 'POST',
      url: '/refresh',
      headers: { 'x-csrf-token': token },
      cookies: { [cookie.name]: cookie.value }
    })
    t.assert.strictEqual(response.statusCode, 200)
    t.assert.deepStrictEqual(response.json(), { ok: 'refresh' })
  })

  await t.test('every method of a multi-method require policy is enforced', async () => {
    for (const method of ['PUT', 'PATCH']) {
      const response = await fastify.inject({ method, url: '/settings' })
      t.assert.strictEqual(response.statusCode, 403)
      t.assert.strictEqual(response.json().message, 'Missing csrf secret')
    }
  })
})

test('route policies: exempt entries skip validation and log the reason', async t => {
  const spyLogger = {
    warn: sinon.spy(),
    error: sinon.spy(),
    info: sinon.spy(),
    debug: sinon.spy(),
    fatal: sinon.spy(),
    trace: sinon.spy(),
    child: () => spyLogger
  }

  const fastify = Fastify({ loggerInstance: spyLogger })
  await fastify.register(fastifyCookie)
  await fastify.register(fastifyCsrf, {
    routePolicies: [
      { url: '/webhooks/:provider', method: 'POST', policy: 'exempt', reason: 'public third-party webhook verified by signature' }
    ]
  })
  fastify.post('/webhooks/:provider', async () => ({ ok: 'webhook' }))
  await fastify.ready()

  const response = await fastify.inject({ method: 'POST', url: '/webhooks/github' })
  t.assert.strictEqual(response.statusCode, 200)
  t.assert.deepStrictEqual(response.json(), { ok: 'webhook' })
  t.assert.strictEqual(spyLogger.warn.callCount, 1)
  t.assert.match(
    spyLogger.warn.firstCall.firstArg,
    /CSRF protection exempt for POST \/webhooks\/:provider: public third-party webhook verified by signature/
  )
})

test('route policies: safe methods are not protected', async t => {
  const fastify = await buildApp(defaultPolicies(), defaultRoutes)

  for (const method of ['GET', 'HEAD', 'OPTIONS', 'TRACE']) {
    const response = await fastify.inject({ method, url: '/token' })
    t.assert.notStrictEqual(response.statusCode, 403)
  }
})

test('route policies: parameterized and wildcard routes match at runtime', async t => {
  const fastify = await buildApp([
    { url: '/users/:id', method: 'POST', policy: 'require' },
    { url: '/webhooks/*', method: 'POST', policy: 'exempt', reason: 'public webhook endpoint' }
  ], (app) => {
    app.post('/users/:id', async () => ({ ok: 'user' }))
    app.post('/webhooks/github/events', async () => ({ ok: 'webhook' }))
  })

  await t.test('parameterized require policy is enforced', async () => {
    const response = await fastify.inject({ method: 'POST', url: '/users/42' })
    t.assert.strictEqual(response.statusCode, 403)
  })

  await t.test('wildcard exempt policy is applied', async () => {
    const response = await fastify.inject({ method: 'POST', url: '/webhooks/github/events' })
    t.assert.strictEqual(response.statusCode, 200)
  })
})

test('route policies: omitting method applies the policy to every supported method', async t => {
  const fastify = await buildApp([
    { url: '/items', policy: 'require' }
  ], (app) => {
    app.route({
      method: ['DELETE', 'GET', 'HEAD', 'OPTIONS', 'PATCH', 'POST', 'PUT', 'QUERY', 'TRACE'],
      url: '/items',
      handler: async () => ({ ok: 'items' })
    })
  })

  const response = await fastify.inject({ method: 'POST', url: '/items' })
  t.assert.strictEqual(response.statusCode, 403)
  t.assert.strictEqual(response.json().message, 'Missing csrf secret')
})

test('route policies: configuration is validated while registering', async t => {
  const cases = [
    ['routePolicies should be an array', { routePolicies: {} }],
    ['routePolicies entries should be objects', { routePolicies: [42] }],
    ['routePolicies entry url should be a non-empty string', { routePolicies: [{ url: '', method: 'POST', policy: 'require' }] }],
    ["routePolicies entry policy should be either 'require' or 'exempt'", { routePolicies: [{ url: '/x', method: 'POST', policy: 'off' }] }],
    ["routePolicies 'exempt' entries require a non-empty 'reason' string", { routePolicies: [{ url: '/x', method: 'POST', policy: 'exempt' }] }],
    ["routePolicies 'exempt' entries require a non-empty 'reason' string", { routePolicies: [{ url: '/x', method: 'POST', policy: 'exempt', reason: '' }] }],
    ["routePolicies 'reason' is only allowed for 'exempt' entries", { routePolicies: [{ url: '/x', method: 'POST', policy: 'require', reason: 'nope' }] }],
    ['routePolicies entry methods should be a string or an array of strings', { routePolicies: [{ url: '/x', method: 42, policy: 'require' }] }],
    ["routePolicies entry method 'BOGUS' is not a valid HTTP method", { routePolicies: [{ url: '/x', method: 'BOGUS', policy: 'require' }] }],
    ['routePolicies entry methods should not be an empty array', { routePolicies: [{ url: '/x', method: [], policy: 'require' }] }]
  ]

  for (const [message, options] of cases) {
    await t.test(message, async () => {
      const fastify = Fastify()
      await t.assert.rejects((async () => {
        await fastify.register(fastifyCookie)
        await fastify.register(fastifyCsrf, options)
        await fastify.ready()
      })(), (err) => err.message === message)
    })
  }

  await t.test('duplicate method and url entries are rejected', async () => {
    const fastify = Fastify()
    await t.assert.rejects((async () => {
      await fastify.register(fastifyCookie)
      await fastify.register(fastifyCsrf, {
        routePolicies: [
          { url: '/x', method: 'POST', policy: 'require' },
          { url: '/x', method: 'POST', policy: 'exempt', reason: 'duplicate' }
        ]
      })
      fastify.post('/x', async () => ({}))
      await fastify.ready()
    })(), /Method 'POST' already declared for route '\/x'/)
  })

  await t.test('entries without a matching route fail before the first request', async () => {
    const fastify = Fastify()
    await fastify.register(fastifyCookie)
    await fastify.register(fastifyCsrf, {
      routePolicies: [{ url: '/ghost', method: 'POST', policy: 'require' }]
    })
    await t.assert.rejects(
      fastify.ready(),
      (err) => err.message === 'routePolicies entry for POST /ghost does not match a registered route'
    )
  })

  await t.test('lowercase method names are normalized', async () => {
    const fastify = Fastify()
    await fastify.register(fastifyCookie)
    await fastify.register(fastifyCsrf, {
      routePolicies: [{ url: '/x', method: 'post', policy: 'require' }]
    })
    fastify.post('/x', async () => ({}))
    await t.assert.doesNotReject(fastify.ready())
  })
})

test('route policies: hooks stay inside the encapsulated plugin scope', async t => {
  const root = Fastify()
  await root.register(fastifyCookie)
  root.post('/outer', async () => ({ ok: 'outer' }))

  await root.register(async function api (app) {
    await app.register(fastifyCsrf, {
      routePolicies: [
        { url: '/api/webhooks/*', method: 'POST', policy: 'exempt', reason: 'public webhook' }
      ]
    })
    app.post('/inner', async () => ({ ok: 'inner' }))
    app.post('/webhooks/github', async () => ({ ok: 'webhook' }))
  }, { prefix: '/api' })

  await root.ready()

  await t.test('routes outside the scope are not affected', async () => {
    const response = await root.inject({ method: 'POST', url: '/outer' })
    t.assert.strictEqual(response.statusCode, 200)
  })

  await t.test('routes inside the scope keep the default protection', async () => {
    const response = await root.inject({ method: 'POST', url: '/api/inner' })
    t.assert.strictEqual(response.statusCode, 403)
  })

  await t.test('the scoped exempt policy still applies', async () => {
    const response = await root.inject({ method: 'POST', url: '/api/webhooks/github' })
    t.assert.strictEqual(response.statusCode, 200)
  })
})

test('route policies: the global hook is not installed without policies', async t => {
  const fastify = Fastify()
  await fastify.register(fastifyCookie)
  await fastify.register(fastifyCsrf)
  fastify.post('/open', async () => ({ ok: 'open' }))
  await fastify.ready()

  const response = await fastify.inject({ method: 'POST', url: '/open' })
  t.assert.strictEqual(response.statusCode, 200)
})

test('route policies: the per-route csrfProtection decorator keeps working', async t => {
  const fastify = Fastify()
  await fastify.register(fastifyCookie)
  await fastify.register(fastifyCsrf, { routePolicies: defaultPolicies() })
  defaultRoutes(fastify)
  fastify.route({
    method: 'POST',
    url: '/decorated',
    onRequest: fastify.csrfProtection,
    handler: async () => ({ ok: 'decorated' })
  })
  await fastify.ready()

  const response = await fastify.inject({ method: 'POST', url: '/decorated' })
  t.assert.strictEqual(response.statusCode, 403)
  t.assert.strictEqual(response.json().message, 'Missing csrf secret')
})
