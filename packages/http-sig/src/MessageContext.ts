import { VerificationError, RequestTarget } from './types'

export class MessageContext {
  private headers: Map<string, string[]>

  constructor() {
    this.headers = new Map()
  }

  requestTarget({ method, path }: RequestTarget): MessageContext {
    this.headers.set('(request-target)', [`${method.toLowerCase()} ${path}`])
    return this
  }

  header(name: string, value: string): MessageContext {
    const normalizedName = name.toLowerCase()
    const currentValues = this.headers.get(normalizedName) || []

    // Push header without any leading/trailing whitespace
    currentValues.push(value.trim())
    this.headers.set(normalizedName, currentValues)

    return this
  }

  signatureString(headers: string[]): string {
    const mergedHeaders = headers.map((h) => {
      const lowerName = h.toLowerCase()
      const headerValues = this.headers.get(lowerName)

      if (headerValues === undefined) throw new VerificationError(`attempted to sign missing header '${h}'`)

      // Header must not have trailing whitespace if empty
      return `${lowerName}: ${headerValues.join(', ')}`.trimRight()
    })

    return mergedHeaders.join('\n')
  }
}
