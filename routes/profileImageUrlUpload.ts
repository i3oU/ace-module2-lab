/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import net from 'node:net'
import dns from 'node:dns/promises'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateOrReservedIp (ip: string): boolean {
  if (ip.toLowerCase().startsWith('::ffff:')) {
    const rest = ip.substring(7)
    if (net.isIPv4(rest)) {
      return isPrivateOrReservedIp(rest)
    }
    const hexParts = rest.split(':')
    if (hexParts.length === 2) {
      const high = parseInt(hexParts[0], 16)
      const low = parseInt(hexParts[1], 16)
      if (!isNaN(high) && !isNaN(low)) {
        const a = (high >> 8) & 0xff
        const b = high & 0xff
        const c = (low >> 8) & 0xff
        const d = low & 0xff
        return isPrivateOrReservedIp(`${a}.${b}.${c}.${d}`)
      }
    }
  }

  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(n => Number(n))
    if (parts.length !== 4 || parts.some(n => isNaN(n) || n < 0 || n > 255)) return true
    const [a, b, c] = parts
    if (a === 0) return true
    if (a === 10) return true
    if (a === 100 && b >= 64 && b <= 127) return true
    if (a === 127) return true
    if (a === 169 && b === 254) return true
    if (a === 172 && b >= 16 && b <= 31) return true
    if (a === 192 && b === 0 && c === 0) return true
    if (a === 192 && b === 0 && c === 2) return true
    if (a === 192 && b === 168) return true
    if (a === 198 && (b === 18 || b === 19)) return true
    if (a === 198 && b === 51 && c === 100) return true
    if (a === 203 && b === 0 && c === 113) return true
    if (a >= 224 && a <= 239) return true
    if (a >= 240) return true
    return false
  }

  if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase()
    if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') return true
    if (normalized === '::' || normalized === '0:0:0:0:0:0:0:0') return true
    if (/^f[cd][0-9a-f]{2}:/i.test(normalized) || normalized.startsWith('fc') || normalized.startsWith('fd')) return true
    if (/^fe[89ab][0-9a-f]:/i.test(normalized) || /^fe[89ab]::/i.test(normalized)) return true
    if (normalized.startsWith('ff')) return true
    if (normalized.startsWith('100::')) return true
    if (normalized.startsWith('2001:db8:') || normalized.startsWith('2001:0db8:')) return true
    return false
  }

  return true
}

async function isSafeUrl (urlString: string): Promise<boolean> {
  let parsed: URL
  try {
    parsed = new URL(urlString)
  } catch {
    return false
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return false
  }

  const rawHost = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (!rawHost) {
    return false
  }

  if (
    rawHost === 'localhost' ||
    rawHost.endsWith('.localhost') ||
    rawHost.endsWith('.local') ||
    rawHost.endsWith('.internal') ||
    rawHost.endsWith('.lan') ||
    rawHost.endsWith('.localdomain') ||
    rawHost === 'metadata.google.internal'
  ) {
    return false
  }

  if (net.isIP(rawHost)) {
    if (isPrivateOrReservedIp(rawHost)) {
      return false
    }
  }

  try {
    const addresses = await dns.lookup(rawHost, { all: true })
    if (!addresses || addresses.length === 0) {
      return false
    }
    for (const addr of addresses) {
      if (isPrivateOrReservedIp(addr.address)) {
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
      if (typeof url === 'string' && url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (typeof url === 'string' && (await isSafeUrl(url))) {
          try {
            const response = await fetch(url)
            if (!response.ok || !response.body) {
              throw new Error('url returned a non-OK status code or an empty body')
            }
            const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
            const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
            await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
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
          logger.warn(`Blocked potentially malicious URL for profile image: ${url}`)
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
