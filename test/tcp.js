const { verifyChecksum } = require('../tcp')
const { ok } = require('assert')

const testData1 = Buffer.from([0x9a,0x56,0x0b,0x8e,0xd,0xcc])
const testChecksum1 = Buffer.from([0x4c,0x4f])

ok(verifyChecksum(testData1, testChecksum1.readUInt16BE()))

console.log('TCP tests pass')
