#ifndef AEGIS_PCAP_READER_H
#define AEGIS_PCAP_READER_H

#include <cstdint>
#include <string>
#include <vector>
#include <fstream>

namespace Aegis {

/**
 * @brief PCAP Global Header.
 * Represents the 24-byte header at the beginning of a PCAP file.
 */
struct alignas(4) PcapGlobalHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

/**
 * @brief PCAP Packet Header.
 * Represents the 16-byte header preceding each packet.
 */
struct alignas(4) PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

/**
 * @brief Represents a single captured packet with metadata.
 */
struct RawPacket {
    PcapPacketHeader header;
    std::vector<uint8_t> data;
};

/**
 * @brief Reads a PCAP file iteratively reading packet streams.
 * Eliminates libpcap dependencies by handling ingestion manually 
 * via std::ifstream binary modes and native endianness checks.
 */
class PcapReader {
public:
    PcapReader() = default;
    ~PcapReader();

    /**
     * @brief Opens a PCAP file for reading.
     * @param filename Path to PCAP file.
     * @return true if successful, false otherwise.
     */
    bool open(const std::string& filename);
    
    /**
     * @brief Closes the currently opened PCAP file.
     */
    void close();
    
    /**
     * @brief Reads the next packet from the file stream.
     * @param packet Destination structure to populate.
     * @return true if a packet was successfully imported.
     */
    bool readNextPacket(RawPacket& packet);
    
    /**
     * @brief Retrieves the parsed global header metadata.
     */
    const PcapGlobalHeader& getGlobalHeader() const { return global_header_; }
    
    /**
     * @brief Checks if a PCAP file is currently open.
     */
    bool isOpen() const { return file_.is_open(); }
    
    /**
     * @brief Returns whether a byte swap is applied for endianness handling.
     */
    bool needsByteSwap() const { return needs_byte_swap_; }

private:
    std::ifstream file_;
    PcapGlobalHeader global_header_;
    bool needs_byte_swap_ = false;
    
    uint16_t maybeSwap16(uint16_t value) const noexcept;
    uint32_t maybeSwap32(uint32_t value) const noexcept;
};

} // namespace Aegis

#endif // AEGIS_PCAP_READER_H
