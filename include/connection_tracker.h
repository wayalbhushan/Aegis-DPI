#ifndef AEGIS_CONNECTION_TRACKER_H
#define AEGIS_CONNECTION_TRACKER_H

#include "types.h"
#include <unordered_map>
#include <shared_mutex>
#include <vector>
#include <chrono>
#include <functional>

namespace Aegis {

/**
 * @brief Thread-local connection tracker for traffic inspection routing.
 * Ensures stateful, multi-stage packet processing logic across flow lifetimes.
 */
class ConnectionTracker {
public:
    explicit ConnectionTracker(int fp_id, size_t max_connections = 100000);
    
    /**
     * @brief Retrieves or initializes a connection tracking entry.
     */
    Connection* getOrCreateConnection(const FiveTuple& tuple);
    
    /**
     * @brief Retrieves an existent flow tracking entry (null if unfound).
     */
    Connection* getConnection(const FiveTuple& tuple);
    
    /**
     * @brief Updates traffic transfer statistics on the connection.
     */
    void updateConnection(Connection* conn, size_t packet_size, bool is_outbound);
    
    /**
     * @brief Marks a connection with specific parsed metadata flags.
     */
    void classifyConnection(Connection* conn, AppType app, const std::string& sni);
    
    /**
     * @brief Modifies connection fate routing to drop subsequent payloads.
     */
    void blockConnection(Connection* conn);
    
    /**
     * @brief Completes flow termination sequence.
     */
    void closeConnection(const FiveTuple& tuple);
    
    /**
     * @brief Garbage collector for stagnant connection flows.
     */
    size_t cleanupStale(std::chrono::seconds timeout = std::chrono::seconds(300));
    
    std::vector<Connection> getAllConnections() const;
    size_t getActiveCount() const;
    
    struct TrackerStats {
        size_t active_connections;
        size_t total_connections_seen;
        size_t classified_connections;
        size_t blocked_connections;
    };
    
    TrackerStats getStats() const;
    void clear();
    void forEach(std::function<void(const Connection&)> callback) const;

private:
    int fp_id_;
    size_t max_connections_;
    
    std::unordered_map<FiveTuple, Connection, FiveTupleHash> connections_;
    
    size_t total_seen_ = 0;
    size_t classified_count_ = 0;
    size_t blocked_count_ = 0;
    
    void evictOldest();
};

/**
 * @brief Centralized aggregator for thread-isolated tracker analytics.
 */
class GlobalConnectionTable {
public:
    explicit GlobalConnectionTable(size_t num_fps);
    
    void registerTracker(int fp_id, ConnectionTracker* tracker);
    
    struct GlobalStats {
        size_t total_active_connections;
        size_t total_connections_seen;
        std::unordered_map<AppType, size_t> app_distribution;
        std::vector<std::pair<std::string, size_t>> top_domains;
    };
    
    GlobalStats getGlobalStats() const;
    std::string generateReport() const;

private:
    std::vector<ConnectionTracker*> trackers_;
    mutable std::shared_mutex mutex_;
};

} // namespace Aegis

#endif // AEGIS_CONNECTION_TRACKER_H
