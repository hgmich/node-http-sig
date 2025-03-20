import { getLastOrOnly } from './common'

describe('common', () => {
  describe('getLastOrOnly', () => {
    it.each([true, undefined, null, 1, 'test', {}])('should return same value if given a scalar (%s)', (input) => {
      expect(getLastOrOnly(input)).toBe(input)
    })

    it.each([true, undefined, null, 1, 'test', {}])('should return last value (%s)', (input) => {
      expect(getLastOrOnly([99, 98, 97, input])).toBe(input)
    })
  })
})
