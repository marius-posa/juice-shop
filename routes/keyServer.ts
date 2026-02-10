/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (file.includes('/') || file.includes('\\')) {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
      return
    }

    if (file.includes('..') || path.isAbsolute(file)) {
      res.status(403)
      next(new Error('File names cannot contain path traversal sequences!'))
      return
    }

    const baseDir = path.resolve('encryptionkeys')
    const resolvedPath = path.resolve(baseDir, file)
    if (!resolvedPath.startsWith(baseDir + path.sep) && resolvedPath !== baseDir) {
      res.status(403)
      next(new Error('File access not allowed!'))
      return
    }

    res.sendFile(resolvedPath)
  }
}
