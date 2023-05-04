import { CREATED_SLACK, EXPIRES_SLACK, Signature } from '../src/Signature'

describe('Signature', () => {
  const lazySignature = (s: string) => () => Signature.fromHeader(s)

  const SECS_MSEC = 1000 // 1000 msec per second
  const MINS_MSEC = 60 * SECS_MSEC // 60 seconds per minute
  const HOURS_MSEC = 60 * MINS_MSEC // 60 minutes per hour
  const DAYS_MSEC = 24 * HOURS_MSEC // 24 hours per day

  test('can parse valid signature with only required fields', () => {
    const signatureString = 'keyId="test",signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="'

    const signature = Signature.fromHeader(signatureString)

    // Check required fields
    expect(signature.keyId).toBe('test')

    const expectedSignatureValue = Buffer.from('3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g=', 'base64')
    expect(signature.signature).toEqual(expectedSignatureValue)

    // Check defaults
    expect(signature.headers).toEqual(['(created)'])

    // Ensure optionals not populated
    expect(signature.signatureAlgorithm).toBeUndefined()
    expect(signature.created).toBeUndefined()
    expect(signature.expires).toBeUndefined()
  })

  test('can parse valid signature with optional fields', () => {
    const signatureString =
      'keyId="test",algorithm="hs2019",headers="(request-target) host (created) (expires) digest",created=0,expires=1999999999,signature="Tm3UfRHt/uk2M7P2OGNcIeejRloPFaBP6HV8Fbtzgc0="'

    const signature = Signature.fromHeader(signatureString)

    expect(signature.keyId).toBe('test')
    expect(signature.signatureAlgorithm).toBe('hs2019')

    // The order here is important
    expect(signature.headers).toEqual(['(request-target)', 'host', '(created)', '(expires)', 'digest'])

    const expectedSignatureValue = Buffer.from('Tm3UfRHt/uk2M7P2OGNcIeejRloPFaBP6HV8Fbtzgc0=', 'base64')
    expect(signature.signature).toEqual(expectedSignatureValue)

    expect(signature.created?.valueOf()).toBe(0)
    expect(signature.expires?.valueOf()).toBe(1999999999000)
  })

  test.each([
    {
      value: '0',
      expected: 0,
    },
    { value: '1234', expected: 1234 },
  ])('can parse valid integer field value $value', ({ value, expected }) => {
    const signatureString = `keyId="test",created=${value},signature="Tm3UfRHt/uk2M7P2OGNcIeejRloPFaBP6HV8Fbtzgc0="`

    const signature = Signature.fromHeader(signatureString)

    expect(signature.created?.valueOf()).toBe(expected * 1000)
  })

  test.each([
    {
      value: '0',
      expected: 0,
    },
    {
      value: '0.0',
      expected: 0,
    },
    {
      value: '1.0',
      expected: 1,
    },
    { value: '1234', expected: 1234 },
    { value: '1234.56', expected: 1234.56 },
  ])('can parse valid decimal field value $value', ({ value, expected }) => {
    const signatureString = `keyId="test",expires=${value},signature="Tm3UfRHt/uk2M7P2OGNcIeejRloPFaBP6HV8Fbtzgc0="`

    const signature = Signature.fromHeader(signatureString)

    expect(signature.expires?.valueOf()).toBe(expected * 1000)
  })

  test('enforces required fields', () => {
    // Missing keyId
    expect(lazySignature('signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="')).toThrowErrorMatchingSnapshot(
      'missing-keyId',
    )

    // Missing signature
    expect(lazySignature('keyId="test"')).toThrowErrorMatchingSnapshot('missing-signature')
  })

  test('forbids whitespacing of fields', () => {
    expect(
      lazySignature('keyId="test", signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="'),
    ).toThrowErrorMatchingSnapshot()
  })

  test('enforces quoting of string fields', () => {
    expect(
      lazySignature('keyId=test,signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="'),
    ).toThrowErrorMatchingSnapshot()
  })

  test('enforces non-quoting of integer fields', () => {
    expect(
      lazySignature(
        'keyId="test",algorithm="hs2019",created="1234",signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="',
      ),
    ).toThrowErrorMatchingSnapshot()
  })

  test('enforces non-quoting of decimal fields', () => {
    expect(
      lazySignature(
        'keyId="test",algorithm="hs2019",expires="1234",signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="',
      ),
    ).toThrowErrorMatchingSnapshot()
  })

  test('enforces number format for integer fields', () => {
    expect(
      lazySignature(
        'keyId="test",algorithm="hs2019",created=1234a,signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="',
      ),
    ).toThrowErrorMatchingSnapshot('non-numeric')

    expect(
      lazySignature(
        'keyId="test",algorithm="hs2019",created=,signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="',
      ),
    ).toThrowErrorMatchingSnapshot('empty-field')

    expect(
      lazySignature('keyId="test",created=01,signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="'),
    ).toThrowErrorMatchingSnapshot('leading-zero')

    expect(
      lazySignature('keyId="test",created=-1,signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="'),
    ).toThrowErrorMatchingSnapshot('negative-integer')
  })

  test('enforces number format for decimal fields', () => {
    expect(
      lazySignature('keyId="test",expires=1234a,signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="'),
    ).toThrowErrorMatchingSnapshot('non-numeric')

    expect(
      lazySignature('keyId="test",expires=1234.56.78,signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="'),
    ).toThrowErrorMatchingSnapshot('multiple-decimal')

    expect(
      lazySignature('keyId="test",expires=,signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="'),
    ).toThrowErrorMatchingSnapshot('empty-field')

    expect(
      lazySignature('keyId="test",expires=.1,signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="'),
    ).toThrowErrorMatchingSnapshot('leading-decimal')

    expect(
      lazySignature('keyId="test"expires=1.,signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="'),
    ).toThrowErrorMatchingSnapshot('trailing-decimal')

    expect(
      lazySignature('keyId="test",expires=-1.0,signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="'),
    ).toThrowErrorMatchingSnapshot('negative-decimal')

    expect(
      lazySignature('keyId="test",expires=.,signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="'),
    ).toThrowErrorMatchingSnapshot('solo-decimal')
  })

  test('enforces correct whitespacing of headers', () => {
    expect(
      lazySignature(
        'keyId="test",headers=" content-type (request-target) host digest",signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="',
      ),
    ).toThrowErrorMatchingSnapshot('no-leading-space')

    expect(
      lazySignature(
        'keyId="test",headers="content-type (request-target) host digest ",signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="',
      ),
    ).toThrowErrorMatchingSnapshot('no-trailing-space')

    expect(
      lazySignature(
        'keyId="test",headers="content-type (request-target) host  digest",signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="',
      ),
    ).toThrowErrorMatchingSnapshot('no-double-space')

    expect(
      lazySignature(
        'keyId="test",algorithm="hs2019",headers="content-type (request-target) host\tdigest",signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="',
      ),
    ).toThrowErrorMatchingSnapshot('no-tab-space')

    expect(
      lazySignature(
        'keyId="test",algorithm="hs2019",headers="content-type (request-target) host\vdigest",signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="',
      ),
    ).toThrowErrorMatchingSnapshot('no-vertical-space')

    expect(
      lazySignature(
        'keyId="test",algorithm="hs2019",headers="content-type (request-target) host\fdigest",signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="',
      ),
    ).toThrowErrorMatchingSnapshot('no-form-feed')

    expect(
      lazySignature(
        'keyId="test",algorithm="hs2019",headers="content-type (request-target) host\u00A0digest",signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="',
      ),
    ).toThrowErrorMatchingSnapshot('no-nbsp')
  })

  test('forbids incorrect field syntax', () => {
    expect(
      lazySignature(',keyId="test",signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="'),
    ).toThrowErrorMatchingSnapshot('no-leading-comma')

    expect(
      lazySignature('keyId="test",signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g=",'),
    ).toThrowErrorMatchingSnapshot('no-trailing-comma')

    expect(
      lazySignature('keyId="test",,signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="'),
    ).toThrowErrorMatchingSnapshot('no-double-comma')
  })

  test('ignores unknown fields', () => {
    expect(
      lazySignature('keyId="test",signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g=",foo="bar"'),
    ).not.toThrow()
  })

  test('forbids duplicate fields', () => {
    expect(
      lazySignature('keyId="test",keyId="test",signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="'),
    ).toThrowErrorMatchingSnapshot()
  })

  test('forbids subsecond precision for created', () => {
    // NB: signature not valid because not needed for this test case
    expect(
      lazySignature('keyId="test",created=1234.56,signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="'),
    ).toThrowErrorMatchingSnapshot()
  })

  test('permit subsecond precision for expires', () => {
    // NB: signature not valid because not needed for this test case

    const makeSig = lazySignature(
      'keyId="test",expires=1234.56,signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="',
    )
    expect(makeSig).not.toThrow()

    const sig = makeSig()
    expect(sig.expires?.valueOf()).toBe(1234560)
  })

  test('correctly detects when creation is invalid due to being in the future', () => {
    // Use 1 day as "the future"
    const futureDate = Math.floor((Date.now() + 1 * DAYS_MSEC) / 1000)
    const signatureString = `keyId="test",created=${futureDate},signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="`

    const signature = Signature.fromHeader(signatureString)
    expect(signature.validCreation).toBe(false)
  })

  test('correctly detects when expiry is invalid due to being is in past', () => {
    const signatureString = 'keyId="test",expires=0,signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="'

    const signature = Signature.fromHeader(signatureString)
    expect(signature.validExpires).toBe(false)
  })

  test('allows configured slack in created timestamp', () => {
    const baseTime = 1000000000000
    const referenceTime = baseTime
    const createdTimestamp = Math.floor((baseTime + CREATED_SLACK) / 1000) - 1 // 1s before slack limit
    const signatureString = `keyId="test",algorithm="hs2019",headers="content-type (created) (request-target) host digest",created=${createdTimestamp},signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="`

    const signature = Signature.fromHeader(signatureString, new Date(referenceTime))
    expect(signature.validCreation).toBe(true)
  })

  test('enforces configured slack in created timestamp', () => {
    const baseTime = 1000000000000
    const referenceTime = baseTime
    const createdTimestamp = Math.floor((baseTime + CREATED_SLACK) / 1000) + 1 // 1s after slack limit
    const signatureString = `keyId="test",algorithm="hs2019",headers="content-type (created) (request-target) host digest",created=${createdTimestamp},signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="`

    const signature = Signature.fromHeader(signatureString, new Date(referenceTime))
    expect(signature.validCreation).toBe(false)
  })

  test('correctly detects when expiry is invalid due to being is in past', () => {
    const signatureString = 'keyId="test",expires=0,signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="'

    const signature = Signature.fromHeader(signatureString)
    expect(signature.validExpires).toBe(false)
  })

  test('allows configured slack in expires timestamp', () => {
    const baseTime = 1000000000000
    const referenceTime = baseTime + EXPIRES_SLACK - 1
    const expiresTimestamp = baseTime / 1000 // 1 ms before slack limit
    const signatureString = `keyId="test",expires=${expiresTimestamp},signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="`

    const signature = Signature.fromHeader(signatureString, new Date(referenceTime))
    expect(signature.validExpires).toBe(true)
  })

  test('enforces configured slack in expires timestamp', () => {
    const baseTime = 1000000000000
    const referenceTime = baseTime + EXPIRES_SLACK + 1 // 1 ms after slack limit
    const expiresTimestamp = baseTime / 1000
    const signatureString = `keyId="test",expires=${expiresTimestamp},signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="`

    const signature = Signature.fromHeader(signatureString, new Date(referenceTime))
    expect(signature.validExpires).toBe(false)
  })

  test('normalizes header case', () => {
    const signatureString = `keyId="test",headers="header-1 HEADER-2 HeAdeR-3",signature="3UqQIVxNJfNm8E54n35RReP9Nv05a9dEZTxr/deog3g="`

    const signature = Signature.fromHeader(signatureString)
  })
})
