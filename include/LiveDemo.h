#ifndef LIVE_DEMO_H
#define LIVE_DEMO_H

// Runs an interactive live demo: prompts for a password attempt against a
// simulated login, feeds each attempt (success or failure) through the
// SAME structures used in the file-based batch mode (Hash Map, Queue
// sliding window, Heap, and the new Hash Set blocklist) in real time.
//
// This exists so a guide/examiner can type wrong passwords themselves
// and watch detection + blocking happen live, instead of only seeing
// output from a pre-made file.
void runLiveDemo();

#endif
