# Aegis DPI - Enterprise Deep Packet Inspection

Aegis is an enterprise-grade, high-performance Deep Packet Inspection (DPI) engine written natively in modern C++17. Engineered for zero-dependency execution and massive concurrency, Aegis safely analyzes network streams identifying application semantics without decrypting secure payloads.

---

## 📖 Table of Contents
1. [Core Architectural Constraints](#1-core-architectural-constraints)
2. [Advanced Threading Architecture](#2-advanced-threading-architecture)
3. [Deep Dive: Inspecting Packets (SNI)](#3-deep-dive-inspecting-packets-sni)
4. [Zero-Dependency Native Ingestion](#4-zero-dependency-native-ingestion)
5. [Building the Engine](#5-building-the-engine)
6. [Test Cases & Execution](#6-test-cases--execution)
7. [Understanding Live Reports](#7-understanding-live-reports)

---

## 1. Core Architectural Constraints

Aegis was completely rebuilt to optimize around highly stringent memory behaviors critical for network infrastructure security:

*   **Zero External Dependencies**: Bypasses `libpcap` and `boost`. PCAP ingestion is strictly localized using binary `std::ifstream` mapped explicitly against endian-checked layouts.
*   **Zero-Allocation Lookups**: Heavy `if-else` flow structures for application detection were replaced with `constexpr std::array` signature tracking and `std::string_view` buffers, meaning payload matching allocations are completely bypassed.
*   **Optimal CPU Cache Constraints**: Central data structures are heavily padded. Connections are bound by `alignas(64)` preventing L1/L2 cache-line false sharing across concurrent Fast Path (FP) logic evaluators. Flow keys (`FiveTuple`) are locked to `alignas(16)`.

---

## 2. Advanced Threading Architecture

Aegis handles raw scale via a mathematically predictable execution topology: Load Balancers (LB) and Fast Path (FP) threads.

### Thread Routing Diagram
```text
                     ┌───────────────────────┐
                     │    Reader Thread      │
                     │  (Ingests binary)     │
                     └───────────┬───────────┘
                                 │
           ┌─────────────────────┴─────────────────────┐
           │        FNV-1a Hash(Five-Tuple) % M        │
           ▼                                           ▼
  ┌─────────────────┐                         ┌─────────────────┐
  │  LB0 Thread     │                         │  LB1 Thread     │
  │ (Load Balancer) │                         │ (Load Balancer) │
  └────────┬────────┘                         └────────┬────────┘
           │                                           │
    ┌──────┴──────┐                             ┌──────┴──────┐
    │  Hash % N   │                             │  Hash % N   │
    ▼             ▼                             ▼             ▼
┌────────┐    ┌────────┐                    ┌────────┐    ┌────────┐
│ FP0    │    │ FP1    │                    │ FP2    │    │ FP3    │
│(Worker)│    │(Worker)│                    │(Worker)│    │(Worker)│
└────┬───┘    └────┬───┘                    └────┬───┘    └────┬───┘
     │             │                             │             │
     └─────────────┴─────────────┬───────────────┴─────────────┘
                                 │
                     ┌───────────▼───────────┐
                     │     Output Queue      │
                     │ (Serialized packets)  │
                     └───────────┬───────────┘
                                 ▼
                          [FILTERED PCAP]
```

### Why FNV-1a Hashing?
Network connections are uniquely identified by a "**5-Tuple**" (Source IP, Dest IP, Source Port, Dest Port, Protocol). Aegis computes a deterministic 64-bit `FNV-1a` hash over these fields. 

Because of this constant evaluation, **Packet X** and **Packet Y** from the same real-life connection are *guaranteed* to be routed through the exact same Load Balancer to the exact same Fast Path. This permits our `ConnectionTracker` in each FP thread to run largely lock-free without globally polling cross-thread connection states.

---

## 3. Deep Dive: Inspecting Packets (SNI)

Even under heavily secured HTTPS traffic, Aegis is capable of transparently classifying apps without breaking TLS encryption by peeking precisely into the `Client Hello` handshake.

### The TLS Handshake Sniffing Protocol
When your network establishes an HTTPS domain call (like `youtube.com` or `facebook.com`), the negotiation sequence begins unencrypted:

```text
-- Client Hello Payload --
Byte 0:     Content Type = 0x16 (Handshake)
Bytes 1-2:  Version = 0x0301 (TLS/SSL)

-- Handshake Layer --
Byte 5:     Type = 0x01 (Client Hello)
...
-- SNI Extension Extraction --
Aegis iterates dynamically over variable length extension offsets (0x0000)
    SNI Type: 0x00 (hostname)
    SNI Value: "www.youtube.com"  <-- Captured implicitly
```

Using this isolated lookup, Aegis tracks and classifies the flow stream securely as `AppType::YOUTUBE`, passing this into the `RuleManager` matrix to assert potential drops over the subsequent streams.

---

## 4. Zero-Dependency Native Ingestion

Typically, network software relies heavily on UNIX sockets or `libpcap`. Aegis avoids this footprint completely through precise byte-mapping:

```text
┌────────────────────────────┐
│ Global Header (24 bytes)   │ <-- Mapped to PcapGlobalHeader, confirms MAGIC (0xa1b2c3d4)
├────────────────────────────┤
│ Packet Header (16 bytes)   │ <-- Extracted timestamps and exact payload inclinations 
│ Packet Data (variable)     │ <-- Native memory block extracted via ifstream read
├────────────────────────────┤
│ ... next headers ...       │
└────────────────────────────┘
```

The system even dynamically monitors Big Endian / Little Endian signatures natively rotating bit shifts if executing across variant architecture infrastructures.

---

## 5. Building the Engine

You only need standard modern CMake and a C++17 compliant compiler.

### Windows (MSVC)
1. Open up a "x64 Native Tools Command Prompt for VS"
2. `$ cd C:\path\to\Aegis-DPI`
3. `$ cmake -B build -S .`
4. `$ cmake --build build --config Release`

### Linux / Windows (MinGW-w64)
1. In your terminal instance: 
2. `$ cmake -G "MinGW Makefiles" -B build -S .`
3. `$ cmake --build build --config Release`

---

## 6. Test Cases & Execution

To effectively test Aegis, supply a recorded `.pcap` trace via Wireshark holding typical browsing activity. The executable is generated at `build/Release/aegis_dpi.exe` (or `build/aegis_dpi`).

### Test Case #1: Complete Application Ban
You want to universally restrict known media patterns from traversing through the infrastructure output.

```cmd
./aegis_dpi traffic.pcap secure_traffic.pcap --block-app YouTube --block-app Netflix
```
*Expected Outcome:* Aegis automatically flags any TLS Client Hellos reporting `.googlevideo.` or `.netflix` signatures and terminates the entire tracked connection output blocks.

### Test Case #2: Advanced Enterprise Topology
Testing Aegis to run across a heavy server with 16 dedicated hardware threads allocating substantial queue scaling. We instruct Aegis block standard Discord and TikTok tracking via domains:

```cmd
./aegis_dpi core.pcap filtered.pcap --lbs 4 --fps 4 --block-domain tiktok.com --block-domain discord.com --block-ip 10.0.0.155
```
*Expected Outcome:* Aegis launches 1 Reader thread, 4 Load Balancers threads, 16 Fast Path threads (4 per LB), and 1 Output Writer. Data will rapidly chunk via the 5-Tuple hashed distribution balancing loads dynamically across evaluating instances. 

---

## 7. Understanding Live Reports

Upon finishing ingestion execution, Aegis dynamically aggregates the threaded statistics securely utilizing atomic operations to finalize a highly readable reporting topology.

```text
╔══════════════════════════════════════════════════════════════╗
║               AEGIS ENGINE STATISTICS                        ║
╠══════════════════════════════════════════════════════════════╣
║ PACKET STATISTICS                                            ║
║   Total Packets:           580234                            ║
║   Total Bytes:             75199201                          ║
║   TCP Packets:             514032                            ║
║   UDP Packets:              66202                            ║
╠══════════════════════════════════════════════════════════════╣
║ FILTERING STATISTICS                                         ║
║   Forwarded:               480000                            ║
║   Dropped/Blocked:         100234                            ║
║   Drop Rate:                17.27%                           ║
╠══════════════════════════════════════════════════════════════╣
║ LOAD BALANCER STATISTICS                                     ║
║   LB Received:             580234                            ║
║   LB Dispatched:           580234                            ║
╚══════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════╗
║                 APPLICATION CLASSIFICATION REPORT            ║
╠══════════════════════════════════════════════════════════════╣
║ Total Connections:        45021                              ║
║ Classified:               21500 (47.8%)                      ║
║ Unidentified:             23521 (52.2%)                      ║
╠══════════════════════════════════════════════════════════════╣
║                    APPLICATION DISTRIBUTION                  ║
╠══════════════════════════════════════════════════════════════╣
║ YouTube           8400     39.1%  ###################        ║
║ Facebook          5200     24.2%  ############               ║
║ HTTPS             4100     19.1%  #########                  ║
║ Unknown           ...        ...                             ║
╚══════════════════════════════════════════════════════════════╝
```

1. **Packet Breakdowns**: Defines exactly how many packets Aegis bypassed vs evaluated logically. 
2. **Hit/Drop Ratio**: Explicit percentages of identified flagged tuples removed iteratively from the pipeline payload sink.
3. **Application Distribution**: Categorized extraction distributions generated passively purely by inspecting `Client Hello` clear text variants inside heavily encrypted flow topologies. 

---

*For further bug reports, security disclosures, or architecture scaling documentation, open dedicated tracking alerts within the administrative branches.*
