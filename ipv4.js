// http://www.tcpipguide.com/free/t_IPDatagramGeneralFormat.htm

const { parseTCPPacket } = require('./tcp')

const bitSet = (data, check) => (data & check) === check

const FLAGS = {
  0b100: 'Reserved (not used)',
  0b010: 'DF (Don\'t Fragment)',
  0b001: 'MF (More Fragments)',
}

const PROTOCOL = {
  0x00: 'Reserved',
  0x01: 'ICMP',
  0x02: 'IGMP',
  0x03: 'GGP',
  0x04: 'IP-in-IP Encapsulation',
  0x06: 'TCP',
  0x08: 'EGP',
  0x11: 'UDP',
  0x32: 'Encapsulating Security Payload (ESP) Extension Header',
  0x33: 'Authentication Header (AH) Extension Header',
}

// [ flag1, flag2 ]
const parseIPV4Flags = data => Object.keys(FLAGS)
  .filter(FLAGS.hasOwnProperty.bind(FLAGS))
  .map(flag => bitSet(data, FLAGS[flag]))

/*
 * for upper layer checksum
 * 12 bytes
 * - 4byte src address
 * - 4byte dest address
 * - 1byte reserved (all zeros)
 * - 1byte protocol
 * - 2byte tcp length (computed)
 */
const createPseudoHeader = (
  sourceAddress,
  destinationAddress,
  protocolHeader,
  tcpLength
) => {
  const ph = Buffer.alloc(12)
  ph.writeUInt32BE(sourceAddress)
  ph.writeUInt32BE(destinationAddress, 4)
  ph.writeUInt8(protocolHeader, 9) // skip 1byte reserved
  ph.writeUInt16BE(tcpLength, 10)
  return ph
}

const parseIPv4Packet = data => {
  let offset = 0
  const byte0 = data.readUInt8(offset++)
  const version = byte0 >> 4
  const internetHeaderLength = byte0 & 0xF
  const tos = data.readUInt8(offset++)
  const totalLength = data.readUInt16BE(offset+=2)
  const identification = data.readUInt16BE(offset+=2)
  const flagsFragmentOffsetBytes = data.readUInt16BE(offset+=2)
  const flags = parseIPV4Flags(flagsFragmentOffsetBytes >> 3)
  const fragmentOffset = flagsFragmentOffsetBytes & 0x1F
  const ttl = data.readUInt8(offset++)
  const protocolHeader = data.readUInt8(offset++)
  const protocol = PROTOCOL[protocolHeader]
  const headerChecksum = data.readUInt16BE(offset+=2)
  const sourceAddress = data.readUInt32BE(offset+=4)
  const destinationAddress = data.readUInt32BE(offset+=4)
  const optionsLength = internetHeaderLength - 5
  const optionBytes = optionsLength ?
    data.readUInt32BE(offset+=(4*optionsLength)).toString(2) : 0 // with padding

  // for upper layer's checksum
  const pseudoHeader = createPseudoHeader(sourceAddress, destinationAddress, protocolHeader, data.length - offset)

  const payload = parseTCPPacket(data.slice(offset), pseudoHeader)

  return {
    version,
    internetHeaderLength,
    tos,
    totalLength,
    identification,
    flags,
    fragmentOffset,
    ttl,
    protocol,
    headerChecksum,
    sourceAddress,
    destinationAddress,
    optionBytes,
    data: payload
  }
}

module.exports = {
  parseIPv4Packet
}
