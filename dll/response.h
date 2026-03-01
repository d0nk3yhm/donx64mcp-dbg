#pragma once
#ifndef RESPONSE_H
#define RESPONSE_H

#include <string>
#include <sstream>
#include <vector>
#include <cstdio>

// ── JSON Response Builder ────────────────────────────────────────────────
// Hand-rolled, zero dependencies. Outputs valid JSON strings.

class Response {
    std::vector<std::string> fields;

    static std::string escape_json(const std::string& s) {
        std::string out;
        out.reserve(s.size() + 16);
        for (char c : s) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                default:
                    if ((unsigned char)c < 0x20) {
                        char buf[8];
                        snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                        out += buf;
                    } else {
                        out += c;
                    }
            }
        }
        return out;
    }

public:
    Response& add(const std::string& key, const std::string& value) {
        fields.push_back("\"" + key + "\":\"" + escape_json(value) + "\"");
        return *this;
    }

    // Explicit const char* overload — prevents decay to bool overload
    Response& add(const std::string& key, const char* value) {
        return add(key, std::string(value ? value : ""));
    }

    Response& add(const std::string& key, int64_t value) {
        fields.push_back("\"" + key + "\":" + std::to_string(value));
        return *this;
    }

    Response& add(const std::string& key, uint64_t value) {
        fields.push_back("\"" + key + "\":" + std::to_string(value));
        return *this;
    }

    Response& add(const std::string& key, double value) {
        char buf[64];
        snprintf(buf, sizeof(buf), "%.6f", value);
        fields.push_back("\"" + key + "\":" + std::string(buf));
        return *this;
    }

    Response& add(const std::string& key, bool value) {
        fields.push_back("\"" + key + "\":" + std::string(value ? "true" : "false"));
        return *this;
    }

    Response& addHex(const std::string& key, uint64_t value) {
        char buf[32];
        snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)value);
        fields.push_back("\"" + key + "\":\"" + std::string(buf) + "\"");
        return *this;
    }

    // Add a raw JSON value (for nested objects/arrays)
    Response& addRaw(const std::string& key, const std::string& raw_json) {
        fields.push_back("\"" + key + "\":" + raw_json);
        return *this;
    }

    // Add a JSON array of strings
    Response& addArray(const std::string& key, const std::vector<std::string>& items) {
        std::string arr = "[";
        for (size_t i = 0; i < items.size(); i++) {
            if (i > 0) arr += ",";
            arr += "\"" + escape_json(items[i]) + "\"";
        }
        arr += "]";
        fields.push_back("\"" + key + "\":" + arr);
        return *this;
    }

    // Add a JSON array of raw JSON objects (pre-formatted)
    Response& addRawArray(const std::string& key, const std::vector<std::string>& items) {
        std::string arr = "[";
        for (size_t i = 0; i < items.size(); i++) {
            if (i > 0) arr += ",";
            arr += items[i];
        }
        arr += "]";
        fields.push_back("\"" + key + "\":" + arr);
        return *this;
    }

    std::string build() const {
        std::string result = "{";
        for (size_t i = 0; i < fields.size(); i++) {
            if (i > 0) result += ",";
            result += fields[i];
        }
        result += "}";
        return result;
    }

    void clear() { fields.clear(); }
};

// ── Quick helpers ────────────────────────────────────────────────────────

inline std::string SuccessResponse(const std::string& msg = "ok") {
    return Response().add("status", "ok").add("message", msg).build();
}

inline std::string ErrorResponse(const std::string& msg) {
    return Response().add("status", "error").add("message", msg).build();
}

inline std::string hex_string(uint64_t val) {
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)val);
    return buf;
}

inline std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve(len * 3);
    char buf[4];
    for (size_t i = 0; i < len; i++) {
        if (i > 0) out += ' ';
        snprintf(buf, sizeof(buf), "%02X", data[i]);
        out += buf;
    }
    return out;
}

#endif // RESPONSE_H
