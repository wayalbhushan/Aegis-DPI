#ifndef AEGIS_RULE_MANAGER_H
#define AEGIS_RULE_MANAGER_H

#include "types.h"
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <shared_mutex>
#include <mutex>
#include <optional>
#include <vector>
#include <fstream>

namespace Aegis {

/**
 * @brief Manages centralized blocking/filtering rules.
 * Implements concurrent read-write locks for safe parallel Fast Path evaluation.
 */
class RuleManager {
public:
    RuleManager() = default;
    
    void blockIP(uint32_t ip);
    void blockIP(const std::string& ip);
    void unblockIP(uint32_t ip);
    void unblockIP(const std::string& ip);
    bool isIPBlocked(uint32_t ip) const;
    std::vector<std::string> getBlockedIPs() const;
    
    void blockApp(AppType app);
    void unblockApp(AppType app);
    bool isAppBlocked(AppType app) const;
    std::vector<AppType> getBlockedApps() const;
    
    void blockDomain(const std::string& domain);
    void unblockDomain(const std::string& domain);
    bool isDomainBlocked(const std::string& domain) const;
    std::vector<std::string> getBlockedDomains() const;
    
    void blockPort(uint16_t port);
    void unblockPort(uint16_t port);
    bool isPortBlocked(uint16_t port) const;
    
    /**
     * @brief Detailed blocked packet metadata descriptor.
     */
    struct BlockReason {
        enum Type { IP, APP, DOMAIN, PORT } type;
        std::string detail;
    };
    
    /**
     * @brief Evaluates an incoming packet sequence against global registered filters.
     */
    std::optional<BlockReason> shouldBlock(
        uint32_t src_ip,
        uint16_t dst_port,
        AppType app,
        const std::string& domain) const;
    
    bool saveRules(const std::string& filename) const;
    bool loadRules(const std::string& filename);
    void clearAll();
    
    struct RuleStats {
        size_t blocked_ips;
        size_t blocked_apps;
        size_t blocked_domains;
        size_t blocked_ports;
    };
    
    RuleStats getStats() const;

private:
    mutable std::shared_mutex ip_mutex_;
    std::unordered_set<uint32_t> blocked_ips_;
    
    mutable std::shared_mutex app_mutex_;
    std::unordered_set<AppType> blocked_apps_;
    
    mutable std::shared_mutex domain_mutex_;
    std::unordered_set<std::string> blocked_domains_;
    std::vector<std::string> domain_patterns_;
    
    mutable std::shared_mutex port_mutex_;
    std::unordered_set<uint16_t> blocked_ports_;
    
    static uint32_t parseIP(const std::string& ip);
    static std::string ipToString(uint32_t ip);
    static bool domainMatchesPattern(const std::string& domain, const std::string& pattern);
};

} // namespace Aegis

#endif // AEGIS_RULE_MANAGER_H
