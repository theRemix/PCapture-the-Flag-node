<h1 align="center">PCapture the Flag 🏴‍☠️</h1 >

<p align="center">
  <strong>Parsing tcpdump pcap file to reconstruct an image file</strong>
</p>

## Quick Start

```sh
node .
```

## Parsing Packet Capture File

- read pcap file
- parse global header
- parse each captured packet
  - parse Link Layer : ethernet.js
  - parse Network Layer : ipv4.js
  - parse Transport : tcp.js
  - parse Application Layer : http.js
- reconstruct response (app layer receive from server)
  - @TODO, filtering, sorting, error correction

```
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
```
