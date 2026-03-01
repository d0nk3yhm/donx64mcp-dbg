#pragma once
#ifndef SCANNER_H
#define SCANNER_H

#include "globals.h"
#include <string>

std::string CmdScan(uint64_t start, size_t size, const std::string& pattern);
std::string CmdScanAll(uint64_t start, size_t size, const std::string& pattern, int max_results);
std::string CmdStrings(uint64_t start, size_t size, int min_len);
std::string CmdFindStr(uint64_t start, size_t size, const std::string& needle);

#endif // SCANNER_H
