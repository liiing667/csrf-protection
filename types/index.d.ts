/// <reference types="node" />

import { FastifyPluginAsync, FastifyRequest, HTTPMethods } from 'fastify'
import { Options as CSRFOptions } from '@fastify/csrf'
import { CookieSerializeOptions as FastifyCookieSerializeOptions } from '@fastify/cookie'

declare module 'fastify' {
  interface FastifyInstance {
    csrfProtection(req: FastifyRequest, reply: FastifyReply, done: () => void): void;
  }

  interface FastifyReply {
    /**
     * Generate a token and configure the secret if needed
     * @param options Serialize options and userInfo
     */
    generateCsrf(
      options?: fastifyCsrfProtection.CookieSerializeOptions & { userInfo?: string }
    ): string;
  }
}

type FastifyCsrfProtection =
  FastifyPluginAsync<fastifyCsrfProtection.FastifyCsrfProtectionOptions>

declare namespace fastifyCsrfProtection {
  export type CookieSerializeOptions = FastifyCookieSerializeOptions

  export type GetTokenFn = (req: FastifyRequest) => string | void

  export type CsrfRoutePolicyMethod = HTTPMethods | HTTPMethods[]

  interface CsrfRoutePolicyBase {
    /**
     * Route pattern, including route parameters (`:id`) and wildcards (`*`)
     */
    url: string;
    /**
     * HTTP method(s) the policy applies to. Omit it to apply the policy to
     * every method supported by Fastify.
     */
    method?: CsrfRoutePolicyMethod;
  }

  export interface CsrfRequireRoutePolicy extends CsrfRoutePolicyBase {
    /**
     * Enforce the standard CSRF token validation for the route
     */
    policy: 'require';
  }

  export interface CsrfExemptRoutePolicy extends CsrfRoutePolicyBase {
    /**
     * Skip CSRF token validation for the route
     */
    policy: 'exempt';
    /**
     * Mandatory, human-readable explanation of why the route is exempted.
     * Logged every time the exemption is used.
     */
    reason: string;
  }

  export type CsrfRoutePolicy = CsrfRequireRoutePolicy | CsrfExemptRoutePolicy

  interface FastifyCsrfProtectionOptionsBase {
    cookieKey?: string;
    cookieOpts?: CookieSerializeOptions;
    sessionKey?: string;
    getUserInfo?: (req: FastifyRequest) => string;
    getToken?: GetTokenFn;
    /**
     * Route-level CSRF policies. When provided, an `onRequest` hook protects
     * every state-changing route by default and only applies the configured
     * exemptions. Entries are validated at registration time and must match a
     * registered route before the server starts accepting requests.
     */
    routePolicies?: CsrfRoutePolicy[];
  }

  type RequiredCSRFHmac = Omit<CSRFOptions, 'hmacKey' | 'userInfo'> &
    Required<Pick<CSRFOptions, 'hmacKey'>> & { userInfo: true }

  type OptionalCSRFNoUserInfo = Omit<CSRFOptions, 'userInfo'> & {
    userInfo?: false;
  }

  interface FastifyCsrfProtectionOptionsFastifyCookie {
    sessionPlugin?: '@fastify/cookie';
    csrfOpts?: OptionalCSRFNoUserInfo | RequiredCSRFHmac;
  }

  interface FastifyCsrfProtectionOptionsFastifySession {
    sessionPlugin: '@fastify/session';
    csrfOpts?: CSRFOptions;
  }

  interface FastifyCsrfProtectionOptionsFastifySecureSession {
    sessionPlugin: '@fastify/secure-session';
    csrfOpts?: CSRFOptions;
  }

  export type FastifyCsrfProtectionOptions = FastifyCsrfProtectionOptionsBase & (
    FastifyCsrfProtectionOptionsFastifyCookie |
    FastifyCsrfProtectionOptionsFastifySession |
    FastifyCsrfProtectionOptionsFastifySecureSession
  )

  export const fastifyCsrfProtection: FastifyCsrfProtection
  export { fastifyCsrfProtection as default }
}

declare function fastifyCsrfProtection (...params: Parameters<FastifyCsrfProtection>): ReturnType<FastifyCsrfProtection>
export = fastifyCsrfProtection
