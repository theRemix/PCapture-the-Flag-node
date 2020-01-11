// http://www.tcpipguide.com/free/t_IPDatagramGeneralFormat.htm

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
  const protocol = PROTOCOL[data.readUInt8(offset++)]
  const headerChecksum = data.readUInt16BE(offset+=2)
  const sourceAddress = data.readUInt32BE(offset+=4)
  const destinationAddress = data.readUInt32BE(offset+=4)
  const optionsLength = internetHeaderLength - 5
  const optionBytes = optionsLength ?
    data.readUInt32BE(offset+=(4*optionsLength)).toString(2) : 0 // with padding
  const payload = data.slice(offset).toString('hex')

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
    optionBytes,
    payload
  }
}

module.exports = {
  parseIPv4Packet
}
