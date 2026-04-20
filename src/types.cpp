#include "types.h"
#include <sstream>
#include <algorithm>
#include <cctype>
#include <array>

namespace Aegis {

std::string FiveTuple::toString() const {
    std::ostringstream ss;
    auto formatIP = [](uint32_t ip) {
        std::ostringstream s;
        s << ((ip >> 0) & 0xFF) << "."
          << ((ip >> 8) & 0xFF) << "."
          << ((ip >> 16) & 0xFF) << "."
          << ((ip >> 24) & 0xFF);
        return s.str();
    };
    
    ss << formatIP(src_ip) << ":" << src_port
       << " -> "
       << formatIP(dst_ip) << ":" << dst_port
       << " (" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") << ")";
    return ss.str();
}

std::string_view appTypeToString(AppType type) noexcept {
    switch (type) {
        case AppType::UNKNOWN:    return "Unknown";
        case AppType::HTTP:       return "HTTP";
        case AppType::HTTPS:      return "HTTPS";
        case AppType::DNS:        return "DNS";
        case AppType::TLS:        return "TLS";
        case AppType::QUIC:       return "QUIC";
        case AppType::GOOGLE:     return "Google";
        case AppType::FACEBOOK:   return "Facebook";
        case AppType::YOUTUBE:    return "YouTube";
        case AppType::TWITTER:    return "Twitter/X";
        case AppType::INSTAGRAM:  return "Instagram";
        case AppType::NETFLIX:    return "Netflix";
        case AppType::AMAZON:     return "Amazon";
        case AppType::MICROSOFT:  return "Microsoft";
        case AppType::APPLE:      return "Apple";
        case AppType::WHATSAPP:   return "WhatsApp";
        case AppType::TELEGRAM:   return "Telegram";
        case AppType::TIKTOK:     return "TikTok";
        case AppType::SPOTIFY:    return "Spotify";
        case AppType::ZOOM:       return "Zoom";
        case AppType::DISCORD:    return "Discord";
        case AppType::GITHUB:     return "GitHub";
        case AppType::CLOUDFLARE: return "Cloudflare";
        default:                  return "Unknown";
    }
}

struct AppSignature {
    std::string_view signature;
    AppType app_type;
};

// Compile-time array of signatures for O(N) but zero-allocation lookup
static constexpr std::array<AppSignature, 39> APP_SIGNATURES = {{
    {"google", AppType::GOOGLE},
    {"gstatic", AppType::GOOGLE},
    {"googleapis", AppType::GOOGLE},
    {"ggpht", AppType::GOOGLE},
    {"gvt1", AppType::GOOGLE},
    {"youtube", AppType::YOUTUBE},
    {"ytimg", AppType::YOUTUBE},
    {"youtu.be", AppType::YOUTUBE},
    {"yt3.ggpht", AppType::YOUTUBE},
    {"facebook", AppType::FACEBOOK},
    {"fbcdn", AppType::FACEBOOK},
    {"fb.com", AppType::FACEBOOK},
    {"fbsbx", AppType::FACEBOOK},
    {"meta.com", AppType::FACEBOOK},
    {"instagram", AppType::INSTAGRAM},
    {"cdninstagram", AppType::INSTAGRAM},
    {"whatsapp", AppType::WHATSAPP},
    {"wa.me", AppType::WHATSAPP},
    {"twitter", AppType::TWITTER},
    {"twimg", AppType::TWITTER},
    {"x.com", AppType::TWITTER},
    {"t.co", AppType::TWITTER},
    {"netflix", AppType::NETFLIX},
    {"nflxvideo", AppType::NETFLIX},
    {"nflximg", AppType::NETFLIX},
    {"amazon", AppType::AMAZON},
    {"amazonaws", AppType::AMAZON},
    {"cloudfront", AppType::AMAZON},
    {"aws", AppType::AMAZON},
    {"microsoft", AppType::MICROSOFT},
    {"msn.com", AppType::MICROSOFT},
    {"office", AppType::MICROSOFT},
    {"azure", AppType::MICROSOFT},
    {"live.com", AppType::MICROSOFT},
    {"outlook", AppType::MICROSOFT},
    {"bing", AppType::MICROSOFT},
    {"apple", AppType::APPLE},
    {"icloud", AppType::APPLE},
    {"itunes", AppType::APPLE}
}};

AppType sniToAppType(std::string_view sni) noexcept {
    if (sni.empty()) return AppType::UNKNOWN;
    
    // Convert SNI to lower equivalent iteratively (to avoid allocation)
    auto containsCaseInsensitive = [](std::string_view haystack, std::string_view needle) {
        if (needle.length() > haystack.length()) return false;
        for (size_t i = 0; i <= haystack.length() - needle.length(); ++i) {
            bool match = true;
            for (size_t j = 0; j < needle.length(); ++j) {
                if (std::tolower(haystack[i + j]) != std::tolower(needle[j])) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
    };

    for (const auto& sig : APP_SIGNATURES) {
        if (containsCaseInsensitive(sni, sig.signature)) {
            return sig.app_type;
        }
    }
    
    // Other known simple ones not completely listed above for brevity but required
    if (containsCaseInsensitive(sni, "telegram") || containsCaseInsensitive(sni, "t.me")) return AppType::TELEGRAM;
    if (containsCaseInsensitive(sni, "tiktok") || containsCaseInsensitive(sni, "bytedance")) return AppType::TIKTOK;
    if (containsCaseInsensitive(sni, "spotify") || containsCaseInsensitive(sni, "scdn.co")) return AppType::SPOTIFY;
    if (containsCaseInsensitive(sni, "zoom")) return AppType::ZOOM;
    if (containsCaseInsensitive(sni, "discord")) return AppType::DISCORD;
    if (containsCaseInsensitive(sni, "github")) return AppType::GITHUB;
    if (containsCaseInsensitive(sni, "cloudflare") || containsCaseInsensitive(sni, "cf-")) return AppType::CLOUDFLARE;
    
    return AppType::HTTPS;
}

} // namespace Aegis
