#include "load_balancer.h"
#include <iostream>

namespace Aegis {

LoadBalancer::LoadBalancer(int lb_id, std::vector<ThreadSafeQueue<PacketJob>*> fp_queues, int fp_start_id)
    : lb_id_(lb_id), fp_start_id_(fp_start_id), num_fps_(fp_queues.size()), fp_queues_(std::move(fp_queues)), input_queue_(10000) {
    per_fp_counts_.resize(num_fps_, 0);
}

LoadBalancer::~LoadBalancer() {
    stop();
}

void LoadBalancer::start() {
    if (running_) return;
    running_ = true;
    thread_ = std::thread(&LoadBalancer::run, this);
    std::cout << "[LB" << lb_id_ << "] Started managing " << num_fps_ << " FPs\n";
}

void LoadBalancer::stop() {
    if (!running_) return;
    running_ = false;
    input_queue_.shutdown();
    if (thread_.joinable()) thread_.join();
    std::cout << "[LB" << lb_id_ << "] Stopped\n";
}

void LoadBalancer::run() {
    while (running_) {
        auto job_opt = input_queue_.popWithTimeout(std::chrono::milliseconds(100));
        if (!job_opt) continue;
        
        packets_received_++;
        int fp_index = selectFP(job_opt->tuple);
        fp_queues_[fp_index]->push(std::move(*job_opt));
        
        per_fp_counts_[fp_index]++;
        packets_dispatched_++;
    }
}

int LoadBalancer::selectFP(const FiveTuple& tuple) {
    FiveTupleHash hasher;
    return hasher(tuple) % num_fps_;
}

LoadBalancer::LBStats LoadBalancer::getStats() const {
    LBStats stats;
    stats.packets_received = packets_received_.load();
    stats.packets_dispatched = packets_dispatched_.load();
    for (uint64_t count : per_fp_counts_) stats.per_fp_packets.push_back(count);
    return stats;
}


LBManager::LBManager(int num_lbs, int fps_per_lb, std::vector<ThreadSafeQueue<PacketJob>*> fp_queues)
    : fps_per_lb_(fps_per_lb) {
    for (int i = 0; i < num_lbs; i++) {
        std::vector<ThreadSafeQueue<PacketJob>*> lb_queues;
        int start_idx = i * fps_per_lb;
        for (int j = 0; j < fps_per_lb && (start_idx + j) < static_cast<int>(fp_queues.size()); j++) {
            lb_queues.push_back(fp_queues[start_idx + j]);
        }
        lbs_.push_back(std::make_unique<LoadBalancer>(i, lb_queues, start_idx));
    }
}

LBManager::~LBManager() {
    stopAll();
}

void LBManager::startAll() {
    for (auto& lb : lbs_) lb->start();
}

void LBManager::stopAll() {
    for (auto& lb : lbs_) lb->stop();
}

LoadBalancer& LBManager::getLBForPacket(const FiveTuple& tuple) {
    FiveTupleHash hasher;
    int lb_idx = (hasher(tuple) / fps_per_lb_) % lbs_.size();
    return *lbs_[lb_idx];
}

LBManager::AggregatedStats LBManager::getAggregatedStats() const {
    AggregatedStats stats = {0, 0};
    for (const auto& lb : lbs_) {
        auto lb_stats = lb->getStats();
        stats.total_received += lb_stats.packets_received;
        stats.total_dispatched += lb_stats.packets_dispatched;
    }
    return stats;
}

} // namespace Aegis
