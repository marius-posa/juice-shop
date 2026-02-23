/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import dns from 'node:dns/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateIp (ip: string): boolean {
  // IPv4 private/reserved ranges
  const parts = ip.split('.').map(Number)
  if (parts.length === 4 && parts.every(p => p >= 0 && p <= 255)) {
    if (parts[0] === 10) return true // 10.0.0.0/8
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true // 172.16.0.0/12
    if (parts[0] === 192 && parts[1] === 168) return true // 192.168.0.0/16
    if (parts[0] === 127) return true // 127.0.0.0/8 (loopback)
    if (parts[0] === 169 && parts[1] === 254) return true // 169.254.0.0/16 (link-local)
    if (parts[0] === 0) return true // 0.0.0.0/8
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true // 100.64.0.0/10 (CGNAT)
    if (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19)) return true // 198.18.0.0/15 (benchmark)
    if (parts[0] === 192 && parts[1] === 0 && parts[2] === 0) return true // 192.0.0.0/24 (IETF protocol)
    if (parts[0] === 192 && parts[1] === 0 && parts[2] === 2) return true // 192.0.2.0/24 (documentation)
    if (parts[0] === 198 && parts[1] === 51 && parts[2] === 100) return true // 198.51.100.0/24 (documentation)
    if (parts[0] === 203 && parts[1] === 0 && parts[2] === 113) return true // 203.0.113.0/24 (documentation)
    if (parts[0] >= 224) return true // 224.0.0.0+ (multicast & reserved)
  }
  // IPv6 private/reserved
  const normalizedIp = ip.toLowerCase()
  if (normalizedIp === '::1') return true // loopback
  if (normalizedIp.startsWith('fc') || normalizedIp.startsWith('fd')) return true // unique local
  if (normalizedIp.startsWith('fe80')) return true // link-local
  if (normalizedIp === '::') return true // unspecified
  return false
}

async function isUrlSafe (urlString: string): Promise<boolean> {
  let parsedUrl: URL
  try {
    parsedUrl = new URL(urlString)
  } catch {
    return false
  }

  // Only allow http and https protocols
  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return false
  }

  // Block credentials in URL
  if (parsedUrl.username || parsedUrl.password) {
    return false
  }

  const hostname = parsedUrl.hostname

  // Block direct IP addresses in the URL
  if (isPrivateIp(hostname)) {
    return false
  }

  // Resolve hostname and check all resolved IPs
  try {
    const addresses = await dns.resolve4(hostname).catch(() => [] as string[])
    const addresses6 = await dns.resolve6(hostname).catch(() => [] as string[])
    const allAddresses = [...addresses, ...addresses6]

    if (allAddresses.length === 0) {
      return false
    }

    for (const addr of allAddresses) {
      if (isPrivateIp(addr)) {
        return false
      }
    }
  } catch {
    return false
  }

  return true
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          if (!await isUrlSafe(url)) {
            throw new Error('Blocked request to potentially unsafe URL')
          }
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          await UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
