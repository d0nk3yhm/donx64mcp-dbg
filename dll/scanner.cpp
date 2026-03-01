#include "scanner.h"
#include "memory_ops.h"
#include "response.h"
#include <vector>
#include <cstdio>
#include <cctype>

// ── Parse IDA-style pattern "48 8B 05 ?? ?? ?? ??" ──────────────────────

struct PatternByte {
    uint8_t value;
    bool    wildcard;
};

static bool parse_pattern(const std::string& pattern, std::vector<PatternByte>& out) {
    out.clear();
    size_t i = 0;
    while (i < pattern.size()) {
        // Skip whitespace
        while (i < pattern.size() && (pattern[i] == ' ' || pattern[i] == '\t')) i++;
        if (i >= pattern.size()) break;

        if (pattern[i] == '?') {
            out.push_back({0, true});
            i++;
            if (i < pattern.size() && pattern[i] == '?') i++; // skip second ?
        } else {
            // Parse hex byte
            auto nibble = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            if (i + 1 >= pattern.size()) return false;
            int hi = nibble(pattern[i]);
            int lo = nibble(pattern[i + 1]);
            if (hi < 0 || lo < 0) return false;
            out.push_back({(uint8_t)((hi << 4) | lo), false});
            i += 2;
        }
    }
    return !out.empty();
}

// ── Pattern match at a specific address ─────────────────────────────────

static bool pattern_match(const uint8_t* data, const std::vector<PatternByte>& pattern) {
    for (size_t i = 0; i < pattern.size(); i++) {
        if (!pattern[i].wildcard && data[i] != pattern[i].value)
            return false;
    }
    return true;
}

// ── Scan for pattern ────────────────────────────────────────────────────

std::string CmdScan(uint64_t start, size_t size, const std::string& pattern_str) {
    std::vector<PatternByte> pattern;
    if (!parse_pattern(pattern_str, pattern))
        return ErrorResponse("invalid pattern format (use: 48 8B 05 ?? ?? ?? ??)");

    if (size == 0 || size > 64 * 1024 * 1024)
        return ErrorResponse("invalid size (max 64MB)");

    // Read memory in chunks for safety
    std::vector<uint8_t> buf(size);
    if (!MemReadSafe((void*)start, buf.data(), size))
        return ErrorResponse("failed to read memory region");

    for (size_t i = 0; i <= size - pattern.size(); i++) {
        if (pattern_match(buf.data() + i, pattern)) {
            uint64_t found = start + i;
            return Response()
                .add("status", "ok")
                .addHex("address", found)
                .addHex("rva", found - g_base_address)
                .add("offset", (int64_t)i)
                .build();
        }
    }

    return Response()
        .add("status", "ok")
        .add("message", "pattern not found")
        .addHex("searched_from", start)
        .add("searched_size", (int64_t)size)
        .build();
}

std::string CmdScanAll(uint64_t start, size_t size, const std::string& pattern_str, int max_results) {
    std::vector<PatternByte> pattern;
    if (!parse_pattern(pattern_str, pattern))
        return ErrorResponse("invalid pattern format");

    if (size == 0 || size > 64 * 1024 * 1024)
        return ErrorResponse("invalid size (max 64MB)");
    if (max_results <= 0) max_results = MCP_MAX_SCAN_RESULTS;
    if (max_results > MCP_MAX_SCAN_RESULTS) max_results = MCP_MAX_SCAN_RESULTS;

    std::vector<uint8_t> buf(size);
    if (!MemReadSafe((void*)start, buf.data(), size))
        return ErrorResponse("failed to read memory region");

    std::vector<std::string> results;
    for (size_t i = 0; i <= size - pattern.size() && (int)results.size() < max_results; i++) {
        if (pattern_match(buf.data() + i, pattern)) {
            uint64_t found = start + i;
            results.push_back(
                Response()
                    .addHex("address", found)
                    .addHex("rva", found - g_base_address)
                    .build()
            );
        }
    }

    return Response()
        .add("status", "ok")
        .add("count", (int64_t)results.size())
        .addRawArray("results", results)
        .build();
}

// ── String scanning ─────────────────────────────────────────────────────

std::string CmdStrings(uint64_t start, size_t size, int min_len) {
    if (min_len < 4) min_len = 4;
    if (size == 0 || size > 64 * 1024 * 1024)
        return ErrorResponse("invalid size (max 64MB)");

    std::vector<uint8_t> buf(size);
    if (!MemReadSafe((void*)start, buf.data(), size))
        return ErrorResponse("failed to read memory region");

    std::vector<std::string> results;
    int max_strings = 500;

    // ASCII strings
    std::string current;
    size_t str_start = 0;
    for (size_t i = 0; i < size && (int)results.size() < max_strings; i++) {
        char c = (char)buf[i];
        if (c >= 0x20 && c < 0x7F) {
            if (current.empty()) str_start = i;
            current += c;
        } else {
            if ((int)current.size() >= min_len) {
                // Truncate long strings
                std::string display = current.size() > 128 ? current.substr(0, 128) + "..." : current;
                results.push_back(
                    Response()
                        .addHex("address", start + str_start)
                        .add("type", "ascii")
                        .add("length", (int64_t)current.size())
                        .add("string", display)
                        .build()
                );
            }
            current.clear();
        }
    }

    // Unicode strings (UTF-16LE)
    for (size_t i = 0; i + 1 < size && (int)results.size() < max_strings; i += 2) {
        uint16_t wc = buf[i] | (buf[i + 1] << 8);
        if (wc >= 0x20 && wc < 0x7F) {
            if (current.empty()) str_start = i;
            current += (char)wc;
        } else {
            if ((int)current.size() >= min_len) {
                std::string display = current.size() > 128 ? current.substr(0, 128) + "..." : current;
                results.push_back(
                    Response()
                        .addHex("address", start + str_start)
                        .add("type", "unicode")
                        .add("length", (int64_t)current.size())
                        .add("string", display)
                        .build()
                );
            }
            current.clear();
        }
    }

    return Response()
        .add("status", "ok")
        .add("count", (int64_t)results.size())
        .addRawArray("strings", results)
        .build();
}

std::string CmdFindStr(uint64_t start, size_t size, const std::string& needle) {
    if (needle.empty())
        return ErrorResponse("empty search string");
    if (size == 0 || size > 64 * 1024 * 1024)
        return ErrorResponse("invalid size (max 64MB)");

    std::vector<uint8_t> buf(size);
    if (!MemReadSafe((void*)start, buf.data(), size))
        return ErrorResponse("failed to read memory region");

    std::vector<std::string> results;

    // Search ASCII
    for (size_t i = 0; i <= size - needle.size() && results.size() < 64; i++) {
        if (memcmp(buf.data() + i, needle.c_str(), needle.size()) == 0) {
            results.push_back(
                Response()
                    .addHex("address", start + i)
                    .add("type", "ascii")
                    .build()
            );
        }
    }

    // Search Unicode (UTF-16LE)
    std::wstring wneedle(needle.begin(), needle.end());
    size_t wbytes = wneedle.size() * 2;
    for (size_t i = 0; i + wbytes <= size && results.size() < 64; i += 2) {
        if (memcmp(buf.data() + i, wneedle.c_str(), wbytes) == 0) {
            results.push_back(
                Response()
                    .addHex("address", start + i)
                    .add("type", "unicode")
                    .build()
            );
        }
    }

    return Response()
        .add("status", "ok")
        .add("needle", needle)
        .add("count", (int64_t)results.size())
        .addRawArray("results", results)
        .build();
}
