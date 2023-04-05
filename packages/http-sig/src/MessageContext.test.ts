import { MessageContext } from './MessageContext'

describe('MessageContext', () => {
  test('signature string output matches reference from spec', () => {
    const reference = `(request-target): get /foo
(created): 1402170695
host: example.org
date: Tue, 07 Jun 2014 20:51:35 GMT
cache-control: max-age=60, must-revalidate
x-emptyheader:
x-example: Example header with some whitespace.`

    const headers = ['(request-target)', '(created)', 'host', 'date', 'cache-control', 'x-emptyheader', 'x-example']

    const ctx = new MessageContext()

    ctx
      .requestTarget({ method: 'GET', path: '/foo' })
      .header('(created)', '1402170695')
      .header('Host', 'example.org')
      .header('Date', 'Tue, 07 Jun 2014 20:51:35 GMT')
      .header('X-Example', 'Example header with some whitespace.')
      .header('X-EmptyHeader', '')
      .header('Cache-Control', 'max-age=60')
      .header('Cache-Control', 'must-revalidate')

    expect(ctx.signatureString(headers)).toEqual(reference)
  })
})
