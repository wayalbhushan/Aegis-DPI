#include "dpi_engine.h"
#include <iostream>
#include <string>
#include <vector>

void printUsage(const char* prog) {
    std::cout << "========================================================================\n"
              << "Aegis DPI v1.0 - Multi-threaded Enterprise Deep Packet Inspection\n"
              << "========================================================================\n\n"
              << "Usage: " << prog << " <input.pcap> <output.pcap> [options]\n\n"
              << "Options:\n"
              << "  --block-ip <ip>        Block source IP\n"
              << "  --block-app <app>      Block application (YouTube, Facebook, Netflix, etc.)\n"
              << "  --block-domain <dom>   Block domain (substring match)\n"
              << "  --lbs <n>              Number of Load Balancer threads (default: 2)\n"
              << "  --fps <n>              Fast Path threads per Load Balancer (default: 2)\n\n"
              << "Example:\n"
              << "  " << prog << " capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50\n\n";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printUsage(argv[0]);
        return 1;
    }
    
    std::string input = argv[1];
    std::string output = argv[2];
    
    Aegis::DPIEngine::Config cfg;
    std::vector<std::string> block_ips, block_apps, block_domains;
    
    for (int i = 3; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--block-ip" && i + 1 < argc) block_ips.push_back(argv[++i]);
        else if (arg == "--block-app" && i + 1 < argc) block_apps.push_back(argv[++i]);
        else if (arg == "--block-domain" && i + 1 < argc) block_domains.push_back(argv[++i]);
        else if (arg == "--lbs" && i + 1 < argc) cfg.num_load_balancers = std::stoi(argv[++i]);
        else if (arg == "--fps" && i + 1 < argc) cfg.fps_per_lb = std::stoi(argv[++i]);
    }
    
    Aegis::DPIEngine engine(cfg);
    engine.initialize();
    
    for (const auto& ip : block_ips) engine.blockIP(ip);
    for (const auto& app : block_apps) engine.blockApp(app);
    for (const auto& dom : block_domains) engine.blockDomain(dom);
    
    if (!engine.processFile(input, output)) {
        return 1;
    }
    
    std::cout << "\nOutput successfully written to: " << output << "\n";
    return 0;
}
