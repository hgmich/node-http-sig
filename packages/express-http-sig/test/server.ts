import * as crypto from 'crypto'

import {
  DigestAlgorithm,
  HmacAlgorithm,
  HttpSigVersion,
  SignatureAlgorithm,
  VerificationError,
} from '@holmesmr/http-sig'

import { httpSignatures } from '..'

import express, { NextFunction, Request, Response } from 'express'

const app = express()

const createSymmetricKey = ({ value, encoding }: { value: string; encoding: 'hex' | 'base64' }) =>
  crypto.createSecretKey(Buffer.from(value, encoding))

const { responseSigner, requestSigEnforcer, digestRequestBody } = httpSignatures({
  version: HttpSigVersion.DRAFT_CAVAGE_12,
  signatureAlgorithm: SignatureAlgorithm.HS2019,
  keyId: 'foo',
  digest: DigestAlgorithm.SHA256,
  algorithm: HmacAlgorithm.SHA256,
  key: createSymmetricKey({
    encoding: 'base64',
    value: 'SPJp2BUqwI0bFSe/+mh3vKq5yk0eVOG+2fsIqgcgo7s=',
  }),
})

const goodRoutes = express.Router()

goodRoutes.use(
  // verifySignature is a helper passed in the verify field of express/body-parser
  // middleware. This is necessary to verify request bodies.
  express.json({
    verify: digestRequestBody,
  }),
  // signatureEnforcer verifies that incoming requests are signed.
  requestSigEnforcer,
  // responseSigner handles signing responses produced by your application
  responseSigner,
)

goodRoutes.post('/', (req, res, next) => {
  console.log('Got POST with body:', req.body)
  // const ctx = requestMessageWrapper(req)
  // console.log(req.headers)
  // console.log('sig string:', ctx.canonicalString(['(request-target)', 'Host']))
  res.status(202).send({ status: 'ok', signatureVerified: res.locals.signatureVerified })
})

goodRoutes.get('/', (req, res, next) => {
  console.log('Got GET')
  res.send({ status: 'ok', signatureVerified: res.locals.signatureVerified })
})

// Bad routes forgets to add the verify helper for request bodies
const badRoutes = express.Router()

badRoutes.use(
  responseSigner,
  express.json({
    // verify: digestRequestBody,
  }),
  requestSigEnforcer,
)

badRoutes.post('/', (req, res) => {
  console.log('Got POST with body:', req.body)
  res.status(202).send({ status: 'bad', signatureVerified: res.locals.signatureVerified })
})

app.use('/good', goodRoutes)
app.use('/bad', badRoutes)

function errorHandler(err: any, req: Request, res: Response, next: NextFunction) {
  if (res.headersSent) {
    return next(err)
  }

  let status = 500
  if (err instanceof VerificationError) {
    status = 403
  }
  res.status(status)
  res.send({ error: err.message })
}

app.use(errorHandler)

app.listen(3000, () => {
  console.log('Starting test server on port 3000')
})
