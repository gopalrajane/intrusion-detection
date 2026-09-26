#include "MergeSort.h"

void MergeSort::sort(std::vector<LogEntry>& entries) {
    if (entries.size() <= 1) return;
    mergeSortHelper(entries, 0, static_cast<int>(entries.size()) - 1);
}

void MergeSort::mergeSortHelper(std::vector<LogEntry>& entries, int left, int right) {
    if (left >= right) return;

    int mid = left + (right - left) / 2;
    mergeSortHelper(entries, left, mid);
    mergeSortHelper(entries, mid + 1, right);
    merge(entries, left, mid, right);
}

void MergeSort::merge(std::vector<LogEntry>& entries, int left, int mid, int right) {
    std::vector<LogEntry> leftHalf(entries.begin() + left, entries.begin() + mid + 1);
    std::vector<LogEntry> rightHalf(entries.begin() + mid + 1, entries.begin() + right + 1);

    size_t i = 0, j = 0;
    int k = left;

    while (i < leftHalf.size() && j < rightHalf.size()) {
        if (leftHalf[i].timeInSeconds <= rightHalf[j].timeInSeconds) {
            entries[k++] = leftHalf[i++];
        } else {
            entries[k++] = rightHalf[j++];
        }
    }

    while (i < leftHalf.size()) entries[k++] = leftHalf[i++];
    while (j < rightHalf.size()) entries[k++] = rightHalf[j++];
}
