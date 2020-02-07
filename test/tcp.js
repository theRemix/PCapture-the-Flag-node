const { verifyChecksum } = require('../tcp')
const { ok } = require('assert')

const pseudoHeader1 = Buffer.from([0x9a,0x56])
const testData1 = Buffer.from([0x0b,0x8e,0xd,0xcc])
const testChecksum1 = Buffer.from([0x4c,0x4f])

const pseudoHeader2 = Buffer.from('c0a80065c01efc9a0006002c', 'hex')
const testData2 = Buffer.from('e79f00505eab226500000000b002ffff58230000020405b4010303050101080a3a4dbdc50000000004020000', 'hex')
const testChecksum2 = Buffer.from('5823', 'hex')

ok(verifyChecksum(pseudoHeader1, testData1, testChecksum1.readUInt16BE()))
ok(verifyChecksum(pseudoHeader2, testData2, testChecksum2.readUInt16BE()))

console.log('TCP tests pass')
