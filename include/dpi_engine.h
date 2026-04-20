#ifndef AEGIS_DPI_ENGINE_H
#define AEGIS_DPI_ENGINE_H

#include "types.h"
#include "pcap_reader.h"
#include "packet_parser.h"
#include "load_balancer.h"
#include "fast_path.h"
#include "rule_manager.h"
#include "connection_tracker.h"
#include <memory>
#include <thread>
#include <atomic>
#include <fstream>
#include <mutex>
#include <string>

namespace Aegis {

/**
 * @brief Scalable Engine for Stateful Deep Packet Inspection.
 * Manages the full packet lifecycle: ingestion, thread pooling, load balancing,
 * deep routing, blocking/classifying rules, and resulting packet writing.
 */
class DPIEngine {
public:
    /**
     * @brief High-performance configuration matrix.
     */
    struct Config {
        int num_load_balancers = 2;
        int fps_per_lb = 2;
        size_t queue_size = 10000;
        std::string rules_file;
        bool verbose = false;
    };
    
    explicit DPIEngine(const Config& config);
    ~DPIEngine();
    
    /**
     * @brief Allocates all queues and thread descriptors locally prior to spawn.
     */
    bool initialize();
    
    /**
     * @brief Process a full source PCAP dump, writing unblocked flows to sink.
     */
    bool processFile(const std::string& input_file, 
                     const std::string& output_file);
    
    void start();
    void stop();
    void waitForCompletion();
    
    void blockIP(const std::string& ip);
    void unblockIP(const std::string& ip);
    void blockApp(AppType app);
    void blockApp(const std::string& app_name);
    void unblockApp(AppType app);
    void unblockApp(const std::string& app_name);
    void blockDomain(const std::string& domain);
    void unblockDomain(const std::string& domain);
    
    bool loadRules(const std::string& filename);
    bool saveRules(const std::string& filename);
    
    [[nodiscard]] std::string generateReport() const;
    [[nodiscard]] std::string generateClassificationReport() const;
    [[nodiscard]] const DPIStats& getStats() const;
    void printStatus() const;
    
    [[nodiscard]] RuleManager& getRuleManager() { return *rule_manager_; }
    [[nodiscard]] const Config& getConfig() const { return config_; }
    [[nodiscard]] bool isRunning() const { return running_; }

private:
    Config config_;
    
    std::unique_ptr<RuleManager> rule_manager_;
    std::unique_ptr<GlobalConnectionTable> global_conn_table_;
    
    std::unique_ptr<FPManager> fp_manager_;
    std::unique_ptr<LBManager> lb_manager_;
    
    ThreadSafeQueue<PacketJob> output_queue_;
    std::thread output_thread_;
    std::ofstream output_file_;
    std::mutex output_mutex_;
    
    DPIStats stats_;
    
    std::atomic<bool> running_{false};
    std::atomic<bool> processing_complete_{false};
    std::thread reader_thread_;
    
    void outputThreadFunc();
    void handleOutput(const PacketJob& job, PacketAction action);
    bool writeOutputHeader(const PcapGlobalHeader& header);
    void writeOutputPacket(const PacketJob& job);
    
    void readerThreadFunc(const std::string& input_file);
    PacketJob createPacketJob(const RawPacket& raw, const ParsedPacket& parsed, uint32_t packet_id);
};

} // namespace Aegis

#endif // AEGIS_DPI_ENGINE_H
