
const TCPFlags = {
  0b100000: 'URG',
  0b010000: 'ACK',
  0b001000: 'PSH',
  0b000100: 'RST',
  0b000010: 'SYN',
  0b000001: 'FIN',
}

// [flag1, flag2, ...]
const parseTCPFlags = bits =>
  Object.keys(TCPFlags)
    .filter(k => bits & k)
    .map(k => TCPFlags[k])

const parseTCPPacket = (data, pseudoHeader) => {
  let offset = 0
  const sourcePort = data.readUInt16BE(offset)
  const destinationPort = data.readUInt16BE(offset+=2)
  const seq = data.readUInt32BE(offset+=2)
  const ack = data.readUInt32BE(offset+=4)
  const offsetResFlagBits = data.readUInt16BE(offset+=4)
  const dataOffset = (offsetResFlagBits >> 12) // Header Length
  const headerLength = dataOffset * 4
  const flags = parseTCPFlags(offsetResFlagBits & 0x3f)
  const window = data.readUInt16BE(offset+=2)
  const checksum = data.readUInt16BE(offset+=2)
  const urgentPointer = data.readUInt16BE(offset+=2)

  const checksumVerified = verifyChecksum(
    Buffer.concat([pseudoHeader, data], pseudoHeader.length + data.length),
    checksum
  )

  let payload = null
  if(data.length > headerLength){
    // @TODO parse options
    payload = data.slice(offset+2)
  }

  return {
    sourcePort,
    destinationPort,
    seq,
    ack,
    dataOffset,
    flags,
    window,
    checksum,
    checksumVerified,
    urgentPointer,
    data: payload,
  }
}

/*
 * - tcpPacket:
 *   - 12 byte pseudo header from IP headers
 *   - the rest of the tcp packet bytes
 *   - checksum field is assumed to be all 0s during calculation
 * - verification:
 *   - split tcpPacket into 16bit sets
 *   - add each 16bit set together
 *   - add tcpChecksum (one's complement of previous sets)
 *   - return true if answer is 0xffff
 */
const verifyChecksum = (tcpPacket, tcpChecksum) =>
  (new Array(Math.ceil(tcpPacket.length / 2))
    .fill(null)
    .map((_, i) => tcpPacket.readUInt16BE(i*2))
    .reduce((checksum, sub) => checksum + sub)
    ^ 0xffff) === tcpChecksum
    // or: add tcpChecksum should equal 0xffff

module.exports = {
  parseTCPPacket,
  verifyChecksum
}
