#include "rule_manager.h"
#include <sstream>
#include <iostream>

namespace Aegis {

uint32_t RuleManager::parseIP(const std::string& ip) {
    uint32_t result = 0;
    int octet = 0;
    int shift = 0;
    for (char c : ip) {
        if (c == '.') {
            result |= (octet << shift);
            shift += 8;
            octet = 0;
        } else if (c >= '0' && c <= '9') {
            octet = octet * 10 + (c - '0');
        }
    }
    result |= (octet << shift);
    return result;
}

std::string RuleManager::ipToString(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip >> 0) & 0xFF) << "."
       << ((ip >> 8) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 24) & 0xFF);
    return ss.str();
}

bool RuleManager::domainMatchesPattern(const std::string& domain, const std::string& pattern) {
    if (pattern.empty()) return false;
    if (pattern[0] == '*') {
        if (pattern.length() == 1) return true;
        std::string suffix = pattern.substr(1);
        if (domain.length() >= suffix.length()) {
            return domain.compare(domain.length() - suffix.length(), suffix.length(), suffix) == 0;
        }
        return false;
    }
    return domain == pattern;
}

void RuleManager::blockIP(uint32_t ip) {
    std::unique_lock<std::shared_mutex> lock(ip_mutex_);
    blocked_ips_.insert(ip);
}

void RuleManager::blockIP(const std::string& ip) { blockIP(parseIP(ip)); }

void RuleManager::unblockIP(uint32_t ip) {
    std::unique_lock<std::shared_mutex> lock(ip_mutex_);
    blocked_ips_.erase(ip);
}

void RuleManager::unblockIP(const std::string& ip) { unblockIP(parseIP(ip)); }

bool RuleManager::isIPBlocked(uint32_t ip) const {
    std::shared_lock<std::shared_mutex> lock(ip_mutex_);
    return blocked_ips_.find(ip) != blocked_ips_.end();
}

std::vector<std::string> RuleManager::getBlockedIPs() const {
    std::shared_lock<std::shared_mutex> lock(ip_mutex_);
    std::vector<std::string> result;
    for (uint32_t ip : blocked_ips_) result.push_back(ipToString(ip));
    return result;
}

void RuleManager::blockApp(AppType app) {
    std::unique_lock<std::shared_mutex> lock(app_mutex_);
    blocked_apps_.insert(app);
}

void RuleManager::unblockApp(AppType app) {
    std::unique_lock<std::shared_mutex> lock(app_mutex_);
    blocked_apps_.erase(app);
}

bool RuleManager::isAppBlocked(AppType app) const {
    if (app == AppType::UNKNOWN) return false;
    std::shared_lock<std::shared_mutex> lock(app_mutex_);
    return blocked_apps_.find(app) != blocked_apps_.end();
}

std::vector<AppType> RuleManager::getBlockedApps() const {
    std::shared_lock<std::shared_mutex> lock(app_mutex_);
    return std::vector<AppType>(blocked_apps_.begin(), blocked_apps_.end());
}

void RuleManager::blockDomain(const std::string& domain) {
    std::unique_lock<std::shared_mutex> lock(domain_mutex_);
    if (domain.find('*') != std::string::npos) domain_patterns_.push_back(domain);
    else blocked_domains_.insert(domain);
}

void RuleManager::unblockDomain(const std::string& domain) {
    std::unique_lock<std::shared_mutex> lock(domain_mutex_);
    blocked_domains_.erase(domain);
    for (auto it = domain_patterns_.begin(); it != domain_patterns_.end();) {
        if (*it == domain) it = domain_patterns_.erase(it);
        else ++it;
    }
}

bool RuleManager::isDomainBlocked(const std::string& domain) const {
    if (domain.empty()) return false;
    std::shared_lock<std::shared_mutex> lock(domain_mutex_);
    if (blocked_domains_.find(domain) != blocked_domains_.end()) return true;
    for (const auto& pattern : domain_patterns_) {
        if (domainMatchesPattern(domain, pattern)) return true;
    }
    return false;
}

std::vector<std::string> RuleManager::getBlockedDomains() const {
    std::shared_lock<std::shared_mutex> lock(domain_mutex_);
    std::vector<std::string> result(blocked_domains_.begin(), blocked_domains_.end());
    result.insert(result.end(), domain_patterns_.begin(), domain_patterns_.end());
    return result;
}

void RuleManager::blockPort(uint16_t port) {
    std::unique_lock<std::shared_mutex> lock(port_mutex_);
    blocked_ports_.insert(port);
}

void RuleManager::unblockPort(uint16_t port) {
    std::unique_lock<std::shared_mutex> lock(port_mutex_);
    blocked_ports_.erase(port);
}

bool RuleManager::isPortBlocked(uint16_t port) const {
    std::shared_lock<std::shared_mutex> lock(port_mutex_);
    return blocked_ports_.find(port) != blocked_ports_.end();
}

std::optional<RuleManager::BlockReason> RuleManager::shouldBlock(
    uint32_t src_ip, uint16_t dst_port, AppType app, const std::string& domain) const {
    
    if (isIPBlocked(src_ip)) return BlockReason{BlockReason::IP, ipToString(src_ip)};
    if (isPortBlocked(dst_port)) return BlockReason{BlockReason::PORT, std::to_string(dst_port)};
    if (isAppBlocked(app)) return BlockReason{BlockReason::APP, std::string(appTypeToString(app))};
    if (isDomainBlocked(domain)) return BlockReason{BlockReason::DOMAIN, domain};
    return std::nullopt;
}

RuleManager::RuleStats RuleManager::getStats() const {
    RuleStats stats;
    { std::shared_lock<std::shared_mutex> lock(ip_mutex_); stats.blocked_ips = blocked_ips_.size(); }
    { std::shared_lock<std::shared_mutex> lock(app_mutex_); stats.blocked_apps = blocked_apps_.size(); }
    { std::shared_lock<std::shared_mutex> lock(domain_mutex_); stats.blocked_domains = blocked_domains_.size() + domain_patterns_.size(); }
    { std::shared_lock<std::shared_mutex> lock(port_mutex_); stats.blocked_ports = blocked_ports_.size(); }
    return stats;
}

bool RuleManager::saveRules(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) return false;
    
    for (const auto& ip : getBlockedIPs()) file << "IP " << ip << "\n";
    for (AppType app : getBlockedApps()) file << "APP " << appTypeToString(app) << "\n";
    for (const auto& domain : getBlockedDomains()) file << "DOMAIN " << domain << "\n";
    
    std::shared_lock<std::shared_mutex> lock(port_mutex_);
    for (uint16_t port : blocked_ports_) file << "PORT " << port << "\n";
    return true;
}

bool RuleManager::loadRules(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return false;
    
    clearAll();
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream iss(line);
        std::string type, value;
        if (!(iss >> type >> value)) continue;
        
        if (type == "IP") blockIP(value);
        else if (type == "APP") {
            for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
                if (appTypeToString(static_cast<AppType>(i)) == value) {
                    blockApp(static_cast<AppType>(i));
                    break;
                }
            }
        }
        else if (type == "DOMAIN") blockDomain(value);
        else if (type == "PORT") blockPort(std::stoi(value));
    }
    return true;
}

void RuleManager::clearAll() {
    { std::unique_lock<std::shared_mutex> lock(ip_mutex_); blocked_ips_.clear(); }
    { std::unique_lock<std::shared_mutex> lock(app_mutex_); blocked_apps_.clear(); }
    { std::unique_lock<std::shared_mutex> lock(domain_mutex_); blocked_domains_.clear(); domain_patterns_.clear(); }
    { std::unique_lock<std::shared_mutex> lock(port_mutex_); blocked_ports_.clear(); }
}

} // namespace Aegis
