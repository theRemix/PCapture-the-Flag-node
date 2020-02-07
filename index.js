/*
  Main file

  - read pcap file
  - parse global header
  - parse each captured packet
    - parse Link Layer : ethernet.js
    - parse Network Layer : ipv4.js
    - parse Transport : tcp.js
    - parse Application Layer : http.js
  - reconstruct response (app layer received from server)

  parsedPcapFile:
  {
    ...global pcap headers,
    packets: [
      {
        ...ethernet headers,
        ethernetFrame: {
          userData: {
            ...tcp headers,
            payload: Application Layer Data (HTTP)
          }
        }
      }
    ]
  }
*/
const { readFileSync, writeFileSync } = require('fs')
const { join } = require('path')
const { parseGlobalHeader, parsePcapPacket } = require('./pcap')

const capFilePath = join(__dirname, 'data', 'net.cap')
const pcapData = readFileSync(capFilePath)

const globalPcapHeader = parseGlobalHeader(pcapData)

// start offset for packets = 24
const firstPacketOffset = 24
const pcapRecordHeaderSize = 16
const httpBodyDelimiter = Buffer.from('\r\n\r\n')

const isServer = ({
  ethernetFrame: {
    userData: {
      data: {
        sourcePort
      }
    }
  }
}) => sourcePort === 80

const isACK = ({
  ethernetFrame: {
    userData: {
      data: {
        flags
      }
    }
  }
}) => flags.includes('ACK') && !flags.includes('SYN')

const orderBySeq = (tcpA, tcpB) =>
  tcpA.ethernetFrame.userData.data.seq -
  tcpB.ethernetFrame.userData.data.seq

const ipv4ChecksumVerified = ({
  ethernetFrame: {
    userData: {
      checksumVerified
    }
  }
}) => checksumVerified

const tcpChecksumVerified = ({
  ethernetFrame: {
    userData: {
      data: {
        checksumVerified
      }
    }
  }
}) => checksumVerified

const getNextPacket = (packets, offset) => {
  let packet = parsePcapPacket(pcapData, offset)
  if (packet == null) return packets

  return getNextPacket([...packets, packet], offset+packet.length+pcapRecordHeaderSize)
}

const packets = getNextPacket([], firstPacketOffset)
const reconstructedPackets = packets
  .filter(isServer)
  .filter(isACK)
  .sort(orderBySeq)
  .filter(ipv4ChecksumVerified)
  .filter(tcpChecksumVerified)
  .reduce(({uniquePackets, seqs}, packet) => {
    if(seqs.has(packet.ethernetFrame.userData.data.seq)) {
      return { uniquePackets, seqs } // drop duplicate
    }

    seqs.add(packet.ethernetFrame.userData.data.seq)
    return {
      uniquePackets: [...uniquePackets, packet],
      seqs
    }
  }
  , { uniquePackets: [], seqs: new Set() })
  .uniquePackets

let reconstructedPayload = reconstructedPackets
  .map(({
    ethernetFrame: {
      userData: {
        data: {
          data
        }
      }
    }
  }) => data)
  .reduce((httpResponse, data) =>
    Buffer.concat([httpResponse, data])
  , Buffer.from([]))
reconstructedPayload = reconstructedPayload.slice(
  reconstructedPayload.indexOf(httpBodyDelimiter) + httpBodyDelimiter.length
)

const parsedPcapFile = {
  globalPcapHeader,
  packets,
  reconstructedPackets,
  reconstructedPayload,
}

writeFileSync('out.jpg', parsedPcapFile.reconstructedPayload)
