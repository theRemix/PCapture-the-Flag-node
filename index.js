/*
  Main file

  - read pcap file
  - parse global header
  - parse each captured packet
    - parse Link Layer : ethernet.js
    - parse Network Layer : ipv4.js
    - parse Transport : tcp.js
    - parse Application Layer : http.js
  - reconstruct response (app layer receive from server)
    - @TODO, filtering, sorting, error correction

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

const getNextPacket = (packets, offset) => {
  let packet = parsePcapPacket(pcapData, offset)
  if (packet == null) return packets

  return getNextPacket([...packets, packet], offset+packet.length+pcapRecordHeaderSize)
}

const packets = getNextPacket([], firstPacketOffset)
const reconstructedPayload = packets
  .filter(isServer)
  .filter(isACK)
  .sort(orderBySeq)
  .reduce(({uniquePackets, seqs}, {
    ethernetFrame: {
      userData: {
        data
      }
    }
  }) => {
    if(seqs.has(data.seq)) return { uniquePackets, seqs }

    seqs.add(data.seq)
    return {
      uniquePackets: [...uniquePackets, data],
      seqs
    }
  }
  , { uniquePackets: [], seqs: new Set() })
  .uniquePackets
  .reduce((httpResponse, data) =>
    Buffer.concat([httpResponse, data.data])
  , Buffer.from([]))


const parsedPcapFile = {
  globalPcapHeader,
  packets,
  // packets: packets.slice(packets.indexOf(httpBodyDelimiter)+httpBodyDelimiter.length),
  reconstructedPayload,
}

console.log(JSON.stringify(parsedPcapFile.packets, null, 2))

writeFileSync('out.jpg', parsedPcapFile.reconstructedPayload)
