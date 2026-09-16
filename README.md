# PacketScope

PacketScope is a **low-level packet inspection and protocol parsing tool written in Zig**.

The project started as a simple HTTP server experiment and evolved into a deeper exploration of how network protocols are represented, transported, and parsed at the byte level.

The long-term goal is to turn PacketScope into a lightweight packet sniffer capable of capturing raw network traffic and decoding it through a layered protocol stack.

> **Status:** 🚧 Active development

---

## What is PacketScope?

Network packets are ultimately just bytes.

PacketScope is an attempt to make those bytes understandable by progressively decoding each protocol layer:

```text
Raw Packet
    │
    ▼
┌───────────────┐
│   Ethernet    │
└───────┬───────┘
        │ EtherType
        ▼
┌───────────────┐
│     IPv4      │
└───────┬───────┘
        │ Protocol
        ▼
┌───────────────┐
│   Transport   │
│ TCP / UDP ... │
└───────┬───────┘
        │ Payload
        ▼
┌───────────────┐
│ Application   │
│ HTTP / ...    │
└───────────────┘
```

Each layer is parsed independently and passes its payload to the next layer.

---

## Current Progress

PacketScope currently has parsers for several layers of the networking stack.

### Ethernet

The Ethernet parser extracts:

- Destination MAC address
- Source MAC address
- EtherType
- Payload

Currently recognized EtherTypes include:

- IPv4
- ARP
- IPv6
- VLAN
- Unknown EtherTypes

### IPv4

The IPv4 parser handles:

- Version
- IHL / header length
- DSCP / ECN
- Total length
- Identification
- Flags
- Fragment offset
- TTL
- Protocol
- Header checksum
- Source address
- Destination address
- IPv4 options
- Payload

The parser validates header and packet lengths before exposing the payload.

### TCP

The TCP parser currently handles:

- Source port
- Destination port
- Sequence number
- Acknowledgment number
- Data offset
- TCP flags
- Window size
- Checksum
- Urgent pointer
- TCP options
- TCP payload

TCP flags are represented directly using a packed Zig structure.

### HTTP

The original HTTP parser has evolved into the application-layer component of PacketScope.

It currently supports parsing:

- HTTP methods
- HTTP versions
- Request paths
- Headers
- Request bodies

---

## Architecture

PacketScope uses a layered parser architecture.

The top-level parser acts as the orchestrator:

```text
parser.zig
│
├── ethernet.zig
│
├── ipv4.zig
│
├── transport.zig
│   ├── tcp.zig
│   ├── udp.zig        [planned]
│   └── icmp.zig       [planned]
│
└── http.zig
```

The intention is to keep protocol-specific logic inside its own module while allowing `parser.zig` to coordinate the overall packet.

For example:

```text
parser.parse(raw_packet)
        │
        ▼
parseEthernet()
        │
        ▼
EtherType == IPv4
        │
        ▼
ipv4.parse()
        │
        ▼
Protocol == TCP
        │
        ▼
tcp.parse()
        │
        ▼
TCP payload
        │
        ▼
HTTP parser
```

This allows additional protocols to be added without turning the main parser into a monolithic implementation.

---

## Zero-Copy Parsing

One of the core design goals of PacketScope is to avoid unnecessary allocations and data copying.

Protocol parsers return slices into the original packet buffer whenever possible:

```text
Raw packet buffer
┌──────────────────────────────────────────────┐
│ Ethernet │ IPv4 │ TCP │ Application Payload │
└──────────────────────────────────────────────┘
     │         │      │             │
     ▼         ▼      ▼             ▼
    slice     slice  slice         slice
```

For example, the TCP payload is represented as a `[]const u8` slice of the original packet rather than being copied into a new buffer.

This is particularly important for a packet inspection tool where packets may be arriving continuously and allocating/copying data unnecessarily could become expensive.

---

## Error Handling

PacketScope treats malformed packets as part of normal operation rather than assuming that every input is valid.

Protocol parsers validate their input before accessing fields.

Examples include:

```text
PacketTooShort
InvalidVersion
InvalidHeaderLength
TotalLengthMismatch
SegmentTooShort
```

This makes the parsers suitable for eventually processing arbitrary network traffic rather than only carefully constructed test packets.

---

## Testing

PacketScope has a dedicated test suite covering individual protocol parsers as well as complete protocol stacks.

Current tests cover things such as:

- Ethernet header parsing
- IPv4 header parsing
- IPv4 options
- TCP header parsing
- TCP flags
- TCP options
- TCP payloads
- Big-endian network byte order
- Invalid packet lengths
- Zero-copy payload behavior
- Protocol dispatch
- Ethernet → IPv4 → TCP parsing
- Ethernet → IPv4 → TCP → HTTP parsing

The project currently has **64 passing tests**.

Run the test suite with:

```bash
zig build test
```

---

## Why Zig?

PacketScope is also a learning project for understanding systems programming and networking at a lower level.

Zig is particularly interesting for this project because it provides:

- Explicit memory management
- Low-level control over data representation
- Packed structs
- Explicit error handling
- Slices without implicit ownership
- Minimal runtime abstraction
- Easy interoperability with C and system APIs

Network protocols are an especially good environment for exploring these concepts because the programmer has to deal directly with binary data, byte ordering, memory layout, and strict boundaries.

---

## Project Goals

The project is being developed incrementally.

### Phase 1 — Protocol Parsing

- [x] Ethernet parsing
- [x] IPv4 parsing
- [x] TCP parsing
- [x] TCP options
- [x] HTTP parsing
- [x] Protocol-layer integration
- [x] Zero-copy payload handling
- [x] Comprehensive parser tests
- [ ] Transport protocol dispatcher
- [ ] UDP parsing
- [ ] ICMP parsing
- [ ] IPv6 parsing

### Phase 2 — Packet Capture

Move beyond manually supplied byte buffers and capture actual packets from the operating system.

Potential Linux capture mechanisms include:

- Raw sockets
- `AF_PACKET`
- Linux packet sockets
- Berkeley Packet Filter (BPF)

The goal is to connect:

```text
Network Interface
       │
       ▼
Operating System
       │
       ▼
Raw Packet Capture
       │
       ▼
PacketScope Parser
       │
       ▼
Protocol Decoding
```

### Phase 3 — Packet Inspection

Build a usable inspection layer capable of displaying information such as:

```text
Ethernet
  Source:      AA:BB:CC:DD:EE:01
  Destination: AA:BB:CC:DD:EE:02
  Type:        IPv4

IPv4
  Source:      192.168.1.100
  Destination: 192.168.1.1
  Protocol:    TCP
  TTL:         64

TCP
  Source Port:      54321
  Destination Port: 80
  Flags:            PSH, ACK

HTTP
  Method:       GET
  Path:         /hello
  Version:      HTTP/1.1
```

### Phase 4 — Beyond Basic Packet Decoding

Eventually, PacketScope could grow into a more complete network analysis tool with features such as:

- Packet filtering
- Protocol statistics
- TCP stream reconstruction
- Connection tracking
- Packet reassembly
- DNS inspection
- TLS metadata inspection
- PCAP file support
- Packet export
- Interactive terminal UI
- Performance measurements

---

## Design Principles

PacketScope is being built around a few principles:

### 1. Parse, don't copy

Prefer slices into existing packet data instead of allocating new buffers.

### 2. One protocol, one responsibility

Ethernet parsing belongs to the Ethernet module.

IPv4 parsing belongs to the IPv4 module.

TCP parsing belongs to the TCP module.

The top-level parser coordinates them.

### 3. Validate before accessing

A packet is untrusted input.

Lengths, offsets, and protocol fields must be validated before they are used.

### 4. Keep the representation close to the wire

Where appropriate, packet headers are represented using Zig's packed structures so that the relationship between the source code and the actual binary protocol layout remains visible.

### 5. Build incrementally

Each protocol layer is implemented and tested independently before being integrated into the larger stack.

---

## Project Structure

The project currently follows a structure similar to:

```text
PacketScope/
├── src/
│   ├── main.zig
│   ├── root.zig
│   ├── parser.zig
│   ├── ethernet.zig
│   ├── ipv4.zig
│   ├── tcp.zig
│   └── http.zig
│
├── test/
│   ├── root.zig
│   ├── test_stack.zig
│   └── ...
│
├── build.zig
└── README.md
```

---

## Building

Requires:

- [Zig](https://ziglang.org/)
- Linux is the primary target for the eventual packet-capture functionality.

Build the project:

```bash
zig build
```

Run:

```bash
zig build run
```

Run tests:

```bash
zig build test
```

---

## Roadmap

```text
                 ┌──────────────────┐
                 │  Raw Packet Data │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │     Ethernet     │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │       IPv4       │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │    Transport     │
                 │                  │
                 │ TCP │ UDP │ ICMP │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │  Application     │
                 │ HTTP │ DNS │ ... │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │ Packet Inspection│
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │  Live Capture    │
                 │   + Analysis     │
                 └──────────────────┘
```

---

## Motivation

PacketScope is primarily an exploration of **how networking actually works underneath the abstractions we normally use**.

Instead of starting with a high-level networking library, the project works upward from raw bytes:

```text
bytes
 ↓
binary protocol
 ↓
network layer
 ↓
transport layer
 ↓
application protocol
 ↓
network analysis
```

The goal is to understand the machinery underneath tools like packet analyzers while building the tool itself from the ground up.

---

## License

This project is currently under active development.
