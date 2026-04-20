#ifndef AEGIS_SNI_EXTRACTOR_H
#define AEGIS_SNI_EXTRACTOR_H

#include <string>
#include <cstdint>
#include <optional>
#include <vector>

namespace Aegis {

/**
 * @brief Zero-allocation oriented TLS Server Name Indication Extractor
 * Parses TLS Client Hello to extract Server Name.
 */
class SNIExtractor {
public:
    /**
     * @brief Extracts SNI from a TLS Client Hello packet.
     */
    [[nodiscard]] static std::optional<std::string> extract(const uint8_t* payload, size_t length) noexcept;
    
    /**
     * @brief Confirms if payload is a probable TLS Client Hello.
     */
    [[nodiscard]] static bool isTLSClientHello(const uint8_t* payload, size_t length) noexcept;
    
    /**
     * @brief Extracts all extensions for logging/diagnostics.
     */
    [[nodiscard]] static std::vector<std::pair<uint16_t, std::string>> extractExtensions(
        const uint8_t* payload, size_t length);

private:
    static constexpr uint8_t CONTENT_TYPE_HANDSHAKE = 0x16;
    static constexpr uint8_t HANDSHAKE_CLIENT_HELLO = 0x01;
    static constexpr uint16_t EXTENSION_SNI = 0x0000;
    static constexpr uint8_t SNI_TYPE_HOSTNAME = 0x00;
    
    static uint16_t readUint16BE(const uint8_t* data) noexcept;
    static uint32_t readUint24BE(const uint8_t* data) noexcept;
};

/**
 * @brief QUIC SNI Extractor resolving UDP-encapsulated TLS.
 */
class QUICSNIExtractor {
public:
    static std::optional<std::string> extract(const uint8_t* payload, size_t length) noexcept;
    static bool isQUICInitial(const uint8_t* payload, size_t length) noexcept;
};

/**
 * @brief HTTP Host Header Extractor.
 */
class HTTPHostExtractor {
public:
    static std::optional<std::string> extract(const uint8_t* payload, size_t length) noexcept;
    static bool isHTTPRequest(const uint8_t* payload, size_t length) noexcept;
};

/**
 * @brief DNS Query domain extractor.
 */
class DNSExtractor {
public:
    static std::optional<std::string> extractQuery(const uint8_t* payload, size_t length) noexcept;
    static bool isDNSQuery(const uint8_t* payload, size_t length) noexcept;
};

} // namespace Aegis

#endif // AEGIS_SNI_EXTRACTOR_H
