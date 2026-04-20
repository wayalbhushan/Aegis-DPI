#ifndef AEGIS_PLATFORM_H
#define AEGIS_PLATFORM_H

#include <cstdint>

namespace Aegis {
namespace PortableNet {

/**
 * @brief Swaps bytes for a 16-bit integer.
 */
inline uint16_t swapBytes16(uint16_t value) noexcept {
    return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8);
}

/**
 * @brief Swaps bytes for a 32-bit integer.
 */
inline uint32_t swapBytes32(uint32_t value) noexcept {
    return ((value & 0xFF000000) >> 24) |
           ((value & 0x00FF0000) >> 8)  |
           ((value & 0x0000FF00) << 8)  |
           ((value & 0x000000FF) << 24);
}

/**
 * @brief Checks the system byte order at runtime.
 */
inline bool isLittleEndian() noexcept {
    uint16_t test = 0x0001;
    return *reinterpret_cast<uint8_t*>(&test) == 0x01;
}

/**
 * @brief Converts a 16-bit value from network to host byte order.
 */
inline uint16_t netToHost16(uint16_t netValue) noexcept {
    if (isLittleEndian()) {
        return swapBytes16(netValue);
    }
    return netValue;
}

/**
 * @brief Converts a 32-bit value from network to host byte order.
 */
inline uint32_t netToHost32(uint32_t netValue) noexcept {
    if (isLittleEndian()) {
        return swapBytes32(netValue);
    }
    return netValue;
}

/**
 * @brief Converts a 16-bit value from host to network byte order.
 */
inline uint16_t hostToNet16(uint16_t hostValue) noexcept {
    return netToHost16(hostValue);
}

/**
 * @brief Converts a 32-bit value from host to network byte order.
 */
inline uint32_t hostToNet32(uint32_t hostValue) noexcept {
    return netToHost32(hostValue);
}

} // namespace PortableNet
} // namespace Aegis

#endif // AEGIS_PLATFORM_H
