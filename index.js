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

const { readFileSync } = require('fs')
const { join } = require('path')
const { parseGlobalHeader, parsePcapPacket } = require('./pcap')

const capFilePath = join(__dirname, 'data', 'net.cap')
const pcapData = readFileSync(capFilePath)

const globalPcapHeader = parseGlobalHeader(pcapData)

// start offset for packets = 24
let packetOffset = 24

let packet = parsePcapPacket(pcapData, packetOffset)
const packets = []
packets.push(packet)

const parsedPcapFile = {
  globalPcapHeader,
  packets
}

console.log(JSON.stringify(parsedPcapFile, null, 2));
