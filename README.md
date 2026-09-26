# Intelligent Log Analysis & Automatic Intrusion Response System

DSA course project — C++, using Hash Map, BST, Heap, Graph, Queue, and Merge Sort
to detect and simulate response to suspicious login activity in system logs.

## Status: 7 of 8 core structures done
- `LogEntry` / `LogParser` — reads and parses .txt log files
- `MergeSort` — sorts log entries by timestamp (O(n log n), stable)
- `LoginTracker` (Hash Map) — counts failed logins per IP
- `BruteForceDetector` (Queue, sliding window) — flags 3-5+ failures within a time window
- `IPBst` (Binary Search Tree) — stores IPs, supports range queries
- `ThreatPrioritizer` (Heap / priority_queue) — ranks IPs by threat level (HIGH/MEDIUM/LOW)
- `BlockList` (Hash Set) — simulated automatic response / blocklist
- `LiveDemo` — interactive terminal mode: type password attempts, watch detection + blocking happen live

## Still to build
- Graph (adjacency list + BFS/DFS) — coordinated attack cluster detection (multiple IPs targeting the same account)
- `--benchmark` mode (performance comparison)

---

## Two ways to demo this project

### 1. C++ program (the actual graded deliverable)
Run directly with a log file:
```bash
./intrusion_detector data/sample_logs.txt
```
Or run the live interactive terminal mode (type password attempts yourself):
```bash
./intrusion_detector --live
```
Or just run with no arguments to get a menu choosing between the two.

### 2. Visual demo console (`demo/live_demo_console.html`)
A browser-based two-panel dashboard for presenting to your guide: a realistic login form on the left,
and the same detection logic (Hash Map, Queue sliding window, Heap, Hash Set blocklist) visualized
live on the right as you type.

**How to open it:** just double-click `demo/live_demo_console.html` — it opens in any browser, no
server or install needed. It's self-contained (no internet required after opening).

**Correct password for the demo login:** `Secure@123`
**To trigger live blocking:** enter any wrong password 3 times within 45 seconds.

This mirrors the exact same thresholds/logic as the C++ `--live` mode — it exists purely as a
clearer visual for a review/demo, not as a replacement for the C++ implementation, which remains
the actual project deliverable.

---

## Setup in VS Code (one-time, per teammate)

### 1. Install VS Code
https://code.visualstudio.com/

### 2. Install the C/C++ extension
Extensions (`Ctrl+Shift+X`) → search **"C/C++"** (by Microsoft) → Install.

### 3. Install a compiler
- **Windows:** [MinGW-w64](https://www.mingw-w64.org/) (add its `bin` folder to PATH)
- **Mac:** `xcode-select --install`
- **Linux:** `sudo apt install g++ gdb`

Verify: `g++ --version`

### 4. Open this project
`File → Open Folder` → select the `intrusion_detector` folder (the one directly containing
`include/`, `src/`, `.vscode/` — watch out for a double-nested folder after unzipping; if `dir`
doesn't show `src`, `cd intrusion_detector` again first).

---

## Building & running (C++ program)

**Build:** `Ctrl+Shift+B`, or from the terminal:
```bash
g++ -std=c++17 -g -Wall -Iinclude src/main.cpp src/LogEntry.cpp src/LogParser.cpp src/MergeSort.cpp src/LoginTracker.cpp src/BruteForceDetector.cpp src/IPBst.cpp src/ThreatPrioritizer.cpp src/BlockList.cpp src/LiveDemo.cpp -o intrusion_detector
```

**Run (batch mode):**
```bash
./intrusion_detector data/sample_logs.txt
```
Windows: `.\intrusion_detector.exe data/sample_logs.txt`

**Run (live interactive mode):**
```bash
./intrusion_detector --live
```

**Debug:** `F5`

---

## Project structure
```
intrusion_detector/
├── .vscode/          - VS Code build/debug/settings config
├── include/          - header files (.h)
├── src/              - implementation files (.cpp)
├── data/             - sample log files for testing
├── demo/             - browser-based visual demo console for presentations
├── .gitignore
└── README.md
```
