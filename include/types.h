#ifndef AEGIS_TYPES_H
#define AEGIS_TYPES_H

#include <cstdint>
#include <string>
#include <string_view>
#include <functional>
#include <chrono>
#include <vector>
#include <atomic>
#include <optional>

namespace Aegis {

/**
 * @brief Five-Tuple: Uniquely identifies a network connection or flow.
 * Aligned to 16 bytes to enable optimal memory access operations.
 */
struct alignas(16) FiveTuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    
    bool operator==(const FiveTuple& other) const noexcept {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }
    
    FiveTuple reverse() const noexcept {
        return {dst_ip, src_ip, dst_port, src_port, protocol};
    }
    
    std::string toString() const;
};

/**
 * @brief Hash function for FiveTuple.
 * Implements a robust collision-resistant hash (FNV-1a style variants)
 * to maintain consistent flow state across Load Balancers.
 */
struct FiveTupleHash {
    size_t operator()(const FiveTuple& tuple) const noexcept {
        size_t hash = 14695981039346656037ULL;
        auto combine = [&hash](uint32_t val) {
            hash ^= val;
            hash *= 1099511628211ULL;
        };
        combine(tuple.src_ip);
        combine(tuple.dst_ip);
        combine(tuple.src_port);
        combine(tuple.dst_port);
        combine(tuple.protocol);
        return hash;
    }
};

/**
 * @brief Represents detected application types.
 */
enum class AppType {
    UNKNOWN = 0,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    WHATSAPP,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    ZOOM,
    DISCORD,
    GITHUB,
    CLOUDFLARE,
    APP_COUNT
};

std::string_view appTypeToString(AppType type) noexcept;
AppType sniToAppType(std::string_view sni) noexcept;

/**
 * @brief States for deep packet connection tracking.
 */
enum class ConnectionState {
    NEW,
    ESTABLISHED,
    CLASSIFIED,
    BLOCKED,
    CLOSED
};

/**
 * @brief Action representing packet fate.
 */
enum class PacketAction {
    FORWARD,
    DROP,
    INSPECT,
    LOG_ONLY
};

/**
 * @brief Connection metadata tracking flow statistics.
 * Cache line aligned (64 bytes) to prevent false sharing 
 * among Fast Path worker threads tracking connections.
 */
struct alignas(64) Connection {
    FiveTuple tuple;
    ConnectionState state = ConnectionState::NEW;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;
    
    uint64_t packets_in = 0;
    uint64_t packets_out = 0;
    uint64_t bytes_in = 0;
    uint64_t bytes_out = 0;
    
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    
    PacketAction action = PacketAction::FORWARD;
    
    bool syn_seen = false;
    bool syn_ack_seen = false;
    bool fin_seen = false;
};

/**
 * @brief Raw packet job descriptor passed between pipeline threads.
 */
struct PacketJob {
    uint32_t packet_id;
    FiveTuple tuple;
    std::vector<uint8_t> data;
    size_t eth_offset = 0;
    size_t ip_offset = 0;
    size_t transport_offset = 0;
    size_t payload_offset = 0;
    size_t payload_length = 0;
    uint8_t tcp_flags = 0;
    const uint8_t* payload_data = nullptr;
    
    uint32_t ts_sec;
    uint32_t ts_usec;
};

/**
 * @brief Thread-safe statistic aggregations.
 */
struct DPIStats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> forwarded_packets{0};
    std::atomic<uint64_t> dropped_packets{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};
    std::atomic<uint64_t> other_packets{0};
    std::atomic<uint64_t> active_connections{0};
    
    DPIStats() = default;
    DPIStats(const DPIStats&) = delete;
    DPIStats& operator=(const DPIStats&) = delete;
};

} // namespace Aegis

#endif // AEGIS_TYPES_H
