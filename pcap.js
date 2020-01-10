// https://www.tcpdump.org/manpages/pcap-savefile.5.html

const { parseEthernetFrame } = require('./ethernet')

// https://www.tcpdump.org/linktypes.html
const LinkType = {
  0: 'LINKTYPE_NULL',
  1: 'LINKTYPE_ETHERNET'
}

// magic number should be 0x a1 b2 c3 d4
// 0x notation is implicity big endian
// so d4c3b2a1 would be little endian
// https://www.tcpdump.org/manpages/pcap-savefile.5.txt
const parseGlobalHeader = pcap => {
  const magicNumber = pcap.readUInt32LE(0).toString(16); // 4 bytes
  const majorVersion = pcap.readUInt16LE(4); // 2 bytes
  const minorVersion = pcap.readUInt16LE(6); // 2 bytes
  const tzOffset = pcap.readUInt32LE(8); // 4 bytes
  const tsAccuracy = pcap.readUInt32LE(12); // 4 bytes
  const snapshotLength = pcap.readUInt32LE(16); // 4 bytes
  const linkType = pcap.readUInt32LE(20); // 4 bytes

  return {
    magicNumber,
    majorVersion,
    minorVersion,
    tzOffset,
    tsAccuracy,
    snapshotLength,
    linkType: LinkType[linkType],
  }
}

const parsePcapPacket = (pcap, offset) => {
  const timeStampInSeconds = pcap.readUInt32LE(offset)
  const timeStampInMicroseconds = pcap.readUInt32LE(offset+4)
  const packetLength = pcap.readUInt32LE(offset+8)
  const originalPacketLength = pcap.readUInt32LE(offset+12)
  const packetData = pcap.slice(offset+16, offset+16+packetLength)
  const ethernetFrame = parseEthernetFrame(packetData)

  return {
    timeStampInSeconds,
    timeStampInMicroseconds,
    packetLength,
    originalPacketLength,
    ethernetFrame
  }
}

module.exports = {
  parseGlobalHeader,
  parsePcapPacket
}
