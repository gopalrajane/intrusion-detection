#include <iostream>
#include <iomanip>
#include "LogParser.h"
#include "MergeSort.h"
#include "LoginTracker.h"
#include "BruteForceDetector.h"
#include "IPBst.h"
#include "ThreatPrioritizer.h"
#include "BlockList.h"
#include "LiveDemo.h"

static void printHeader(const std::string& title) {
    std::cout << "========================================\n";
    std::cout << " " << title << "\n";
    std::cout << "========================================\n";
}

static void runBatchMode(const std::string& filename) {
    // ---------- 1. PARSE ----------
    printHeader("READING & PARSING LOG FILE");
    std::vector<LogEntry> entries = LogParser::parseFile(filename);
    std::cout << "[FileHandler] Read " << entries.size() << " entries from " << filename << "\n";
    if (LogParser::lastSkippedCount() > 0) {
        std::cout << "[FileHandler] Skipped " << LogParser::lastSkippedCount() << " malformed lines\n";
    }
    std::cout << "\n";

    if (entries.empty()) {
        std::cerr << "No entries to process. Exiting.\n";
        return;
    }

    // ---------- 2. SORT (Merge Sort) ----------
    printHeader("SORTING LOGS BY TIMESTAMP (Merge Sort)");
    MergeSort::sort(entries);
    std::cout << "[MergeSort] O(n log n) -- " << entries.size() << " entries sorted chronologically\n\n";

    // ---------- 3. HASH MAP (failed login counts) ----------
    printHeader("HASH MAP STATE (IP -> Failed Attempts)");
    LoginTracker tracker;
    tracker.process(entries);
    for (const auto& pair : tracker.getAllCounts()) {
        std::cout << pair.first << " -> " << pair.second << "\n";
    }
    std::cout << "[unordered_map] O(1) avg per insert/lookup\n\n";

    // ---------- 4. SLIDING WINDOW (Queue) ----------
    printHeader("SLIDING WINDOW CHECK (Queue, 60s window, threshold 5)");
    BruteForceDetector detector(60, 5);
    detector.process(entries);
    for (const auto& pair : tracker.getAllCounts()) {
        const std::string& ip = pair.first;
        if (detector.isBruteForce(ip)) {
            std::cout << ip << " -> " << detector.getTriggerCount(ip)
                      << " attempts within 60s -> BRUTE FORCE PATTERN\n";
        } else {
            std::cout << ip << " -> " << pair.second
                      << " total attempts -> below threshold\n";
        }
    }
    std::cout << "\n";

    // ---------- 5. BST (IP organization + range query) ----------
    printHeader("BST IN-ORDER TRAVERSAL (Sorted IPs)");
    IPBst bst;
    for (const auto& pair : tracker.getAllCounts()) {
        bst.insert(ipToInt(pair.first));
    }
    std::vector<uint32_t> sortedIps = bst.inOrderTraversal();
    for (size_t i = 0; i < sortedIps.size(); i++) {
        std::cout << intToIp(sortedIps[i]);
        if (i != sortedIps.size() - 1) std::cout << " -> ";
    }
    std::cout << "\n";

    uint32_t low = ipToInt("192.168.1.0");
    uint32_t high = ipToInt("192.168.1.255");
    std::vector<uint32_t> inRange = bst.rangeQuery(low, high);
    std::cout << "[BST.rangeQuery 192.168.1.0-192.168.1.255] -> "
              << inRange.size() << " IPs found in range\n";
    std::cout << "[BST] O(log n) avg insert, O(log n + k) range query\n\n";

    // ---------- 6. HEAP (threat prioritization) ----------
    printHeader("HEAP: THREAT PRIORITIZATION");
    ThreatPrioritizer prioritizer;
    for (const auto& pair : tracker.getAllCounts()) {
        const std::string& ip = pair.first;
        int attempts = pair.second;
        bool bruteForce = detector.isBruteForce(ip);
        ThreatLevel level = ThreatPrioritizer::classify(attempts, bruteForce, false);
        prioritizer.addThreat(ip, attempts, level);
    }

    std::cout << "[priority_queue] O(log n) insert, O(1) peek at highest threat\n";
    std::vector<ThreatEntry> topThreats = prioritizer.getTopN(10);
    int rank = 1;
    for (const auto& t : topThreats) {
        std::cout << rank << ". " << t.ip
                  << " -> " << threatLevelToString(t.level)
                  << " (" << t.failedAttempts << " failed attempts)\n";
        rank++;
    }
    std::cout << "\n";

    // ---------- 7. HASH SET (automatic response / blocklist) ----------
    printHeader("AUTOMATIC RESPONSE (Hash Set Blocklist)");
    BlockList blocklist;
    for (const auto& t : topThreats) {
        if (t.level == ThreatLevel::HIGH) {
            std::string reason = "brute force / HIGH threat (" +
                                  std::to_string(t.failedAttempts) + " failed attempts)";
            blocklist.block(t.ip, reason);
            std::cout << "[BLOCKED] " << t.ip << " -- " << reason << "\n";
        }
    }
    if (blocklist.size() == 0) {
        std::cout << "No IPs met the HIGH threat threshold -- nothing blocked this run.\n";
    }
    std::cout << "[unordered_set] O(1) avg membership check\n\n";

    // ---------- 8. FINAL REPORT ----------
    printHeader("FINAL CYBERSECURITY REPORT");
    std::cout << std::left << std::setw(18) << "IP Address"
              << std::setw(18) << "Failed Attempts"
              << std::setw(14) << "Threat Level"
              << "Status\n";
    for (const auto& t : topThreats) {
        std::string status = blocklist.isBlocked(t.ip) ? "BLOCKED" : "MONITORED";
        std::cout << std::left << std::setw(18) << t.ip
                  << std::setw(18) << t.failedAttempts
                  << std::setw(14) << threatLevelToString(t.level)
                  << status << "\n";
    }
    std::cout << "\nSuspicious IPs Detected: " << topThreats.size() << "\n";
    std::cout << "Total Blocked: " << blocklist.size() << "\n";
    std::cout << "========================================\n";
}

int main(int argc, char* argv[]) {
    // If a file path is given directly, run batch mode immediately
    // (keeps the original usage working: ./intrusion_detector data/sample_logs.txt)
    if (argc >= 2) {
        std::string arg = argv[1];
        if (arg == "--live") {
            runLiveDemo();
        } else {
            runBatchMode(arg);
        }
        return 0;
    }

    // No arguments -- show a menu so the person running it can choose.
    std::cout << "========================================\n";
    std::cout << " INTRUSION DETECTION SYSTEM - MAIN MENU\n";
    std::cout << "========================================\n";
    std::cout << "1. Run batch analysis on a log file\n";
    std::cout << "2. Run live interactive demo (type password attempts yourself)\n";
    std::cout << "Choose an option (1 or 2): ";

    std::string choice;
    std::getline(std::cin, choice);

    if (choice == "2") {
        runLiveDemo();
    } else {
        std::string filename;
        std::cout << "Enter log file path (or press Enter for data/sample_logs.txt): ";
        std::getline(std::cin, filename);
        if (filename.empty()) {
            filename = "data/sample_logs.txt";
        }
        runBatchMode(filename);
    }

    return 0;
}
