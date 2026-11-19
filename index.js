'use strict'

const assert = require('node:assert')
const fp = require('fastify-plugin')
const CSRF = require('@fastify/csrf')
const createError = require('@fastify/error')

const MissingCSRFSecretError = createError('FST_CSRF_MISSING_SECRET', 'Missing csrf secret', 403)
const InvalidCSRFTokenError = createError('FST_CSRF_INVALID_TOKEN', 'Invalid csrf token', 403)
const InvalidCSRFSecretError = createError('FST_CSRF_INVALID_SECRET', 'Invalid csrf secret', 403)

const MIN_SECRET_LENGTH = 16
const MAX_SECRET_LENGTH = 256

function isValidSecret (secret) {
  return typeof secret === 'string' &&
    secret.length >= MIN_SECRET_LENGTH &&
    secret.length <= MAX_SECRET_LENGTH
}

const defaultOptions = {
  cookieKey: '_csrf',
  cookieOpts: { path: '/', sameSite: true, httpOnly: true },
  sessionKey: '_csrf',
  getToken: getTokenDefault,
  getUserInfo: getUserInfoDefault,
  sessionPlugin: '@fastify/cookie',
  logLevel: 'warn'
}

async function fastifyCsrfProtection (fastify, opts) {
  const {
    cookieKey,
    cookieOpts,
    sessionKey,
    getToken,
    getUserInfo,
    sessionPlugin,
    logLevel
  } = Object.assign({}, defaultOptions, opts)

  const csrfOpts = opts?.csrfOpts ? opts.csrfOpts : {}

  assert(typeof cookieKey === 'string', 'cookieKey should be a string')
  assert(typeof sessionKey === 'string', 'sessionKey should be a string')
  assert(typeof getToken === 'function', 'getToken should be a function')
  assert(typeof getUserInfo === 'function', 'getUserInfo should be a function')
  assert(typeof cookieOpts === 'object', 'cookieOpts should be a object')
  assert(typeof logLevel === 'string', 'logLevel should be a string')
  assert(
    ['@fastify/cookie', '@fastify/session', '@fastify/secure-session'].includes(sessionPlugin),
    "sessionPlugin should be one of the following: '@fastify/cookie', '@fastify/session', '@fastify/secure-session'"
  )

  if (opts.getUserInfo) {
    csrfOpts.userInfo = true
  }

  if (sessionPlugin === '@fastify/cookie' && csrfOpts.userInfo) {
    assert(csrfOpts.hmacKey, 'csrfOpts.hmacKey is required')
  }

  const tokens = new CSRF(csrfOpts)

  const isCookieSigned = cookieOpts?.signed

  if (sessionPlugin === '@fastify/secure-session') {
    fastify.decorateReply('generateCsrf', generateCsrfSecureSession)
  } else if (sessionPlugin === '@fastify/session') {
    fastify.decorateReply('generateCsrf', generateCsrfSession)
  } else {
    fastify.decorateReply('generateCsrf', generateCsrfCookie)
  }

  fastify.decorate('csrfProtection', csrfProtection)

  let readSecret

  if (sessionPlugin === '@fastify/secure-session') {
    readSecret = function readSecret (req, _reply) {
      if (!Object.hasOwn(req.session.data(), sessionKey)) {
        return undefined
      }
      return req.session.get(sessionKey)
    }
  } else if (sessionPlugin === '@fastify/session') {
    readSecret = function readSecret (req, _reply) {
      if (!Object.hasOwn(req.session, sessionKey)) {
        return undefined
      }
      return req.session[sessionKey]
    }
  } else {
    readSecret = function readSecret (req, reply) {
      return isCookieSigned
        ? reply.unsignCookie(req.cookies[cookieKey] || '').value
        : req.cookies[cookieKey]
    }
  }

  function getSecret (req, reply) {
    const secret = readSecret(req, reply)
    if (secret === undefined || secret === null || secret === '') {
      return { missing: true }
    }
    if (!isValidSecret(secret)) {
      return { invalid: true }
    }
    return { secret }
  }

  function generateCsrfCookie (opts) {
    const { secret: storedSecret, missing, invalid } = getSecret(this.request, this)
    if (invalid) {
      throw new InvalidCSRFSecretError()
    }
    let secret = storedSecret
    if (missing) {
      secret = tokens.secretSync()
      this.setCookie(cookieKey, secret, Object.assign({}, cookieOpts, opts))
    }
    const userInfo = opts ? opts.userInfo : undefined
    return tokens.create(secret, userInfo)
  }

  function generateCsrfSecureSession (opts) {
    const { secret: storedSecret, missing, invalid } = getSecret(this.request, this)
    if (invalid) {
      throw new InvalidCSRFSecretError()
    }
    let secret = storedSecret
    if (missing) {
      secret = tokens.secretSync()
      this.request.session.set(sessionKey, secret)
    }
    const userInfo = opts ? opts.userInfo : undefined
    if (opts) {
      this.request.session.options(opts)
    }
    return tokens.create(secret, userInfo)
  }

  function generateCsrfSession (opts) {
    const { secret: storedSecret, missing, invalid } = getSecret(this.request, this)
    if (invalid) {
      throw new InvalidCSRFSecretError()
    }
    let secret = storedSecret
    if (missing) {
      secret = tokens.secretSync()
      this.request.session[sessionKey] = secret
    }
    const userInfo = opts ? opts.userInfo : undefined
    return tokens.create(secret, userInfo)
  }

  function csrfProtection (req, reply, next) {
    const { secret, missing, invalid } = getSecret(req, reply)
    if (invalid) {
      req.log[logLevel]('Invalid csrf secret')
      return reply.send(new InvalidCSRFSecretError())
    }
    if (missing) {
      req.log[logLevel]('Missing csrf secret')
      return reply.send(new MissingCSRFSecretError())
    }
    if (!tokens.verify(secret, getToken(req), getUserInfo(req))) {
      req.log[logLevel]('Invalid csrf token')
      return reply.send(new InvalidCSRFTokenError())
    }
    next()
  }
}

function getTokenDefault (req) {
  return req.body?._csrf ||
    req.headers['csrf-token'] ||
    req.headers['xsrf-token'] ||
    req.headers['x-csrf-token'] ||
    req.headers['x-xsrf-token']
}

function getUserInfoDefault (_req) {
  return undefined
}

module.exports = fp(fastifyCsrfProtection, {
  fastify: '5.x',
  name: '@fastify/csrf-protection'
})
module.exports.default = fastifyCsrfProtection
module.exports.fastifyCsrfProtection = fastifyCsrfProtection
