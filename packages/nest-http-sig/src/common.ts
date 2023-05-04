// Copyright (c) Michael Holmes
// SPDX-License-Identifier: MIT

import { VerificationError } from '@holmesmr/http-sig'
import { RawBodyRequest } from '@nestjs/common'
import { Request } from 'express'

export function getLastOrOnly<T>(xs: T | T[] | undefined): T | undefined {
  return Array.isArray(xs) ? xs.slice(-1)[0] : xs
}
