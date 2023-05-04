import { DigestAlgorithm, HmacAlgorithm, HttpSigVersion, MessageContext, SignatureAlgorithm, signatures } from '..'

import * as crypto from 'crypto'

const createSymmetricKey = ({ value, encoding }: { value: string; encoding: 'hex' | 'base64' }) =>
  crypto.createSecretKey(Buffer.from(value, encoding))

const sig = signatures({
  version: HttpSigVersion.DRAFT_CAVAGE_12,
  signatureAlgorithm: SignatureAlgorithm.HS2019,
  keyId: 'test',
  digest: DigestAlgorithm.SHA256,
  algorithm: HmacAlgorithm.SHA256,
  key: createSymmetricKey({
    encoding: 'base64',
    value: 'SPJp2BUqwI0bFSe/+mh3vKq5yk0eVOG+2fsIqgcgo7s=',
  }),
})

const mockRequest = (method: string, path: string, headers: { [header: string]: string[] }) => ({
  requestTarget: { method, path },
  getHeader(header: string): string[] | undefined {
    return headers[header]
  },
})

const headers = {
  'content-type': ['application/json'],
  host: ['foobar.com'],
  digest: ['SHA-256=Qm/ATwS/j9tYMdw3u7bc9w9jo34FpoxupfY+ha5Xk3Y='],
}

sig.getKey('test').then((key) => {
  const msgCtx = new MessageContext(mockRequest('POST', '/', headers))
  console.log(`signature: ${key.signRequest(msgCtx)}`)
})
