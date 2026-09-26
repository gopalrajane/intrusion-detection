#ifndef LOG_PARSER_H
#define LOG_PARSER_H

#include <vector>
#include <string>
#include "LogEntry.h"

class LogParser {
public:
    static std::vector<LogEntry> parseFile(const std::string& filename);
    static int lastSkippedCount();

private:
    static int skippedCount;
};

#endif
