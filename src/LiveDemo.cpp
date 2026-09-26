#include "LiveDemo.h"
#include "LogEntry.h"
#include "LoginTracker.h"
#include "BruteForceDetector.h"
#include "ThreatPrioritizer.h"
#include "BlockList.h"

#include <iostream>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <limits>

namespace {

// Fixed "correct" password for the simulated login -- this is a demo,
// not a real auth system, so it's intentionally simple and visible in code.
const std::string CORRECT_PASSWORD = "Secure@123";
const std::string DEMO_ACCOUNT = "admin";

// Live-demo detector uses a shorter window/lower threshold than the batch
// mode's 60s/5 -- typing 5 attempts within 60 real seconds is easy enough,
// but a tighter 3-within-45s makes the "BLOCKED" moment happen faster and
// feel more responsive during a live demo.
const int LIVE_WINDOW_SECONDS = 45;
const int LIVE_THRESHOLD = 3;

std::string currentTimestamp() {
    std::time_t t = std::time(nullptr);
    std::tm* now = std::localtime(&t);
    std::ostringstream oss;
    oss << std::put_time(now, "%H:%M:%S");
    return oss.str();
}

int currentTimeInSeconds() {
    std::time_t t = std::time(nullptr);
    std::tm* now = std::localtime(&t);
    return now->tm_hour * 3600 + now->tm_min * 60 + now->tm_sec;
}

} // anonymous namespace

void runLiveDemo() {
    std::cout << "\n========================================\n";
    std::cout << " LIVE INTERACTIVE DEMO\n";
    std::cout << "========================================\n";
    std::cout << "Simulated login system. Account: \"" << DEMO_ACCOUNT << "\"\n";
    std::cout << "Enter password attempts. Type 'exit' to stop and see the summary.\n";
    std::cout << "(Hint: try entering the WRONG password 3 times to see live blocking.)\n\n";

    std::string ip;
    std::cout << "Enter a simulated source IP to attach to these attempts\n";
    std::cout << "(or press Enter to use the default 203.0.113.77): ";
    std::getline(std::cin, ip);
    if (ip.empty()) {
        ip = "203.0.113.77";
    }

    LoginTracker tracker;
    BruteForceDetector detector(LIVE_WINDOW_SECONDS, LIVE_THRESHOLD);
    ThreatPrioritizer prioritizer;
    BlockList blocklist;

    int attemptNumber = 0;

    while (true) {
        // ---- Check blocklist FIRST, before even asking for a password ----
        // This mirrors a real system: once blocked, you don't get to try again.
        if (blocklist.isBlocked(ip)) {
            std::cout << "\n[BLOCKED] " << ip << " is already blocked. Reason: "
                      << blocklist.getBlockReason(ip) << "\n";
            std::cout << "Further attempts are being rejected instantly (Hash Set O(1) check).\n";
            std::cout << "Type 'exit' to see the summary, or 'reset' to unblock and continue demo: ";
            std::string cmd;
            std::getline(std::cin, cmd);
            if (cmd == "exit") break;
            if (cmd == "reset") {
                // For demo purposes only -- lets a guide see the flow again
                // without restarting the whole program.
                blocklist = BlockList();
                std::cout << "[DEMO] Blocklist reset for this IP.\n";
                continue;
            }
            continue;
        }

        std::cout << "\nEnter password for \"" << DEMO_ACCOUNT << "\" (or 'exit'): ";
        std::string password;
        std::getline(std::cin, password);

        if (password == "exit") break;

        attemptNumber++;
        std::string ts = currentTimestamp();
        int secs = currentTimeInSeconds();
        bool success = (password == CORRECT_PASSWORD);
        std::string eventType = success ? "SUCCESS_LOGIN" : "FAILED_LOGIN";

        LogEntry entry(ts, secs, eventType, ip, DEMO_ACCOUNT);

        std::cout << "[LOG] " << ts << " " << eventType << " " << ip << " " << DEMO_ACCOUNT << "\n";

        if (success) {
            std::cout << "[RESULT] Login SUCCESSFUL. Access granted.\n";
            continue; // successful logins don't feed the failure-tracking structures
        }

        // ---- Feed this single failed attempt through the real pipeline ----
        std::vector<LogEntry> single = { entry };
        tracker.process(single);     // Hash Map: increments failed count for this IP
        detector.process(single);    // Queue: sliding window check

        int totalFailed = tracker.getFailedCount(ip);
        std::cout << "[HASH MAP] " << ip << " total failed attempts: " << totalFailed << "\n";

        bool bruteForce = detector.isBruteForce(ip);
        if (bruteForce) {
            std::cout << "[QUEUE / SLIDING WINDOW] " << detector.getTriggerCount(ip)
                      << " failures within " << LIVE_WINDOW_SECONDS << "s -> THRESHOLD CROSSED\n";
        } else {
            std::cout << "[QUEUE / SLIDING WINDOW] within threshold (" << LIVE_THRESHOLD
                      << " needed in " << LIVE_WINDOW_SECONDS << "s window)\n";
        }

        ThreatLevel level = ThreatPrioritizer::classify(totalFailed, bruteForce, false);
        prioritizer.addThreat(ip, totalFailed, level);
        std::cout << "[HEAP] Current threat level for " << ip << ": "
                  << threatLevelToString(level) << "\n";

        if (bruteForce && !blocklist.isBlocked(ip)) {
            std::string reason = "brute force: " + std::to_string(detector.getTriggerCount(ip)) +
                                  " failed attempts within " + std::to_string(LIVE_WINDOW_SECONDS) + "s";
            blocklist.block(ip, reason);
            std::cout << "\n[HASH SET / AUTOMATIC RESPONSE] " << ip << " -> BLOCKED\n";
            std::cout << "Reason: " << reason << "\n";
            std::cout << "All further attempts from this IP will now be rejected instantly.\n";
        } else {
            std::cout << "[RESULT] Login FAILED. Try again.\n";
        }
    }

    // ---- Final summary report, same format as the batch/file mode ----
    std::cout << "\n========================================\n";
    std::cout << " LIVE DEMO SUMMARY REPORT\n";
    std::cout << "========================================\n";
    std::cout << std::left << std::setw(18) << "IP Address"
              << std::setw(18) << "Failed Attempts"
              << std::setw(14) << "Threat Level"
              << "Status\n";

    int totalFailed = tracker.getFailedCount(ip);
    if (totalFailed > 0 || blocklist.isBlocked(ip)) {
        ThreatLevel level = ThreatPrioritizer::classify(totalFailed, detector.isBruteForce(ip), false);
        std::string status = blocklist.isBlocked(ip) ? "BLOCKED" : "MONITORED";
        std::cout << std::left << std::setw(18) << ip
                  << std::setw(18) << totalFailed
                  << std::setw(14) << threatLevelToString(level)
                  << status << "\n";
    } else {
        std::cout << "(No failed attempts recorded this session.)\n";
    }

    std::cout << "\nTotal attempts made: " << attemptNumber << "\n";
    std::cout << "Blocklist size: " << blocklist.size() << "\n";
    std::cout << "========================================\n";
}
