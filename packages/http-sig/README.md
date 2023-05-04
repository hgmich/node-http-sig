# `http-sig`

A work-in-progress implementation of the IETF HTTP Signatures draft.

Currently, the only version supported is:

 * HTTP signatures, pre-HTTPbis, draft 12
   ([draft-cavage-http-signatures-12][ietf-http-sig-old-draft-12])

This library may work with implementations conforming to other spec versions;
this is not currently guaranteed

This library is a work-in-progress and not all features are supported!
Additionally, the security and cryptographic integrity have not been vetted or
audited and cannot be guaranteed.

## Getting started

**Note:** Per [Package design](#package-design), you probably don't want to use
this library package; it is intended to be used to implement HTTP signatures
for HTTP frameworks and clients. 

_TODO: list pre-built integrations for nest/express_

Install the `@holmesmr/http-sig` package with your package manager of choice.

## Package design

`http-sig` is an abstract implementation of HTTP signatures that makes no
direct reference to any library or framework, so that the code can be reused
between them without specifics.

_TODO: expand further_

## Supported features

### `algorithm` values

Note: in the language of the HTTP signatures spec, _algorithms_ refer to the
`algorithm` field, which negotiates the cryptography used in the signature.

* `hs2019`, which allows specification of any supported signature algorithm
  and digest algorithm with the understanding that they are agreed for a
  given `keyId` in advance.

* `hmac-sha256`, which forces the use of HMAC-SHA256 as the MAC signature
  algorithm and SHA256 as the digest algorithm, per the spec.


### Cryptography

These are the supported algorithms that may be configured when using the
`hs2019` algorithm.

#### Digest algorithms

_TODO: list_

#### Signature algorithms

Currently, only secret-key based (symmetric) signatures are supported.

##### Secret-key based

_TODO: list_


[ietf-http-sig-old-draft-12]: https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12
