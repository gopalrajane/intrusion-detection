# Intelligent Log Analysis and Intrusion Detection

A C++ project that processes login logs, identifies suspicious authentication activity, and demonstrates a simulated response to potential brute-force attempts.

## Features

- Parse and validate log entries
- Sort events by timestamp using Merge Sort
- Track failed login attempts by IP address
- Detect repeated failures using a queue-based sliding window
- Organize IP addresses with a Binary Search Tree
- Prioritize threats using a heap
- Maintain a simulated blocklist
- Run batch analysis or an interactive demonstration
- Open a browser-based demo from `demo/live_demo_console.html`

## Data Structures and Algorithms

C++, Hash Map, Queue, Binary Search Tree, Heap, Hash Set, and Merge Sort.

## Build

Requires a C++17 compiler.

```bash
g++ -std=c++17 -Wall -Wextra -Iinclude src/main.cpp src/LogEntry.cpp src/LogParser.cpp src/MergeSort.cpp src/LoginTracker.cpp src/BruteForceDetector.cpp src/IPBst.cpp src/ThreatPrioritizer.cpp src/BlockList.cpp src/LiveDemo.cpp -o intrusion_detector
```

## Run

Batch mode:

```bash
./intrusion_detector data/sample_logs.txt
```

Interactive mode:

```bash
./intrusion_detector --live
```

On Windows, run the generated `intrusion_detector.exe`.

## Project Structure

```text
intrusion-detection/
├── data/
├── demo/
├── include/
├── src/
└── README.md
```
