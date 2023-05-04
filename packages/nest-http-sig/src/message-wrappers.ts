// Copyright (c) Michael Holmes
// SPDX-License-Identifier: MIT

import { createMessageContext, MessageContext } from '@holmesmr/http-sig'
import { Request, Response } from 'express'

export function requestMessageWrapper(req: Request): MessageContext {
  return createMessageContext({
    requestTarget: { method: req.method, path: req.path },
    getHeader(name: string) {
      const header = req.headers[name]
      if (typeof header === 'string') {
        return [header]
      }

      return header
    },
  })
}

export function responseMessageWrapper(res: Response): MessageContext {
  return createMessageContext({
    getHeader(name: string) {
      const header = res.getHeader(name)
      if (typeof header === 'string') {
        return [header]
      } else if (typeof header === 'number') {
        return [header.toString()]
      }

      return header
    },
  })
}
