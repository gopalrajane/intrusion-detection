#ifndef MERGE_SORT_H
#define MERGE_SORT_H

#include <vector>
#include "LogEntry.h"

class MergeSort {
public:
    static void sort(std::vector<LogEntry>& entries);

private:
    static void mergeSortHelper(std::vector<LogEntry>& entries, int left, int right);
    static void merge(std::vector<LogEntry>& entries, int left, int mid, int right);
};

#endif
