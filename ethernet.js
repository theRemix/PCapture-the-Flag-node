// https://wiki.wireshark.org/Ethernet

const TYPE = {
  'default': '(IEEE 802.3 and/or 802.2)', // length field
  '0800': 'IP(v4)',
  '0806': 'ARP',
  '8137': 'IPX',
  '86dd': 'IPv6',
}

// { type:TYPE, length:int|null }
// length is null for type field
const parseTypeLength = buf => {
  let type = TYPE['default']
  let length = null

  // is IEE 802.3/802.2 ?
  if(!TYPE.hasOwnProperty(buf.toString('hex'))){
    length = buf.readUInt16BE(0)
  } else {
    type = TYPE[buf.toString('hex')]
  }

  return { type, length }
}

// Preamble is filtered out by Wireshark
const parseEthernetFrame = data => {
  let offset = 0
  const destMACAddr = data.slice(offset, offset+=6).toString('hex')
  const srcMACAddr = data.slice(offset, offset+=6).toString('hex')
  const { type, length } = parseTypeLength(data.slice(offset, offset+=2))
  const userData = data.slice(offset, data.length-32)
  const fcs = data.readUInt32BE(data.length-32)

  return {
    destMACAddr,
    srcMACAddr,
    type,
    length,
    userData: userData.toString('hex'), // @TODO parse in ipv4.js
    fcs
  }
}

module.exports = {
  parseEthernetFrame
}
