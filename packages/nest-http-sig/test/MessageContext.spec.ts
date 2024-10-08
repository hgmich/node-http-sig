import { MessageContext } from '../../http-sig/src/MessageContext'

const mockRequest = (method: string, path: string, headers: { [header: string]: string[] }) => ({
  requestTarget: { method, path },
  getHeader(header: string): string[] | undefined {
    return headers[header]
  },
})

describe('MessageContext', () => {
  test('canonical string output matches reference from spec', () => {
    const reference = `(request-target): get /foo
(created): 1402170695
host: example.org
date: Tue, 07 Jun 2014 20:51:35 GMT
cache-control: max-age=60, must-revalidate
x-emptyheader:
x-example: Example header with some whitespace.`

    const headerList = ['(request-target)', '(created)', 'host', 'date', 'cache-control', 'x-emptyheader', 'x-example']

    const headers = {
      host: ['example.org'],
      date: ['Tue, 07 Jun 2014 20:51:35 GMT'],
      'x-example': ['Example header with some whitespace.'],
      'x-emptyheader': [''],
      'cache-control': ['max-age=60', 'must-revalidate'],
    }
    const ctx = new MessageContext(mockRequest('GET', '/foo', headers), { createdAt: '1402170695' })

    expect(ctx.canonicalString(headerList)).toEqual(reference)
  })
})
