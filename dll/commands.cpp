#include "commands.h"
#include "globals.h"
#include "response.h"
#include "memory_ops.h"
#include "disasm.h"
#include "scanner.h"
#include "modules.h"
#include "breakpoints.h"
#include "threads.h"
#include "hooks.h"
#include "heap.h"
#include "anti_debug.h"

#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <cstdio>

// ── Parse command into tokens ───────────────────────────────────────────

static std::vector<std::string> Tokenize(const std::string& cmd) {
    std::vector<std::string> tokens;
    std::istringstream iss(cmd);
    std::string token;
    while (iss >> token) {
        tokens.push_back(token);
    }
    return tokens;
}

static uint64_t ParseAddr(const std::string& s) {
    return strtoull(s.c_str(), nullptr, 16);
}

static int ParseInt(const std::string& s, int default_val = 0) {
    if (s.empty()) return default_val;
    // Support hex (0x...) and decimal
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        return (int)strtoull(s.c_str(), nullptr, 16);
    return atoi(s.c_str());
}

static std::string GetArg(const std::vector<std::string>& t, int idx, const std::string& def = "") {
    return (idx < (int)t.size()) ? t[idx] : def;
}

// Rejoin tokens from index onward (for string arguments with spaces)
static std::string JoinFrom(const std::vector<std::string>& t, int idx) {
    std::string result;
    for (int i = idx; i < (int)t.size(); i++) {
        if (!result.empty()) result += " ";
        result += t[i];
    }
    return result;
}

// ═════════════════════════════════════════════════════════════════════════
// Master Dispatcher
// ═════════════════════════════════════════════════════════════════════════

std::string DispatchCommand(const std::string& command) {
    auto tokens = Tokenize(command);
    if (tokens.empty())
        return ErrorResponse("empty command");

    std::string cmd = tokens[0];
    std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::toupper);

    // ── Basic ────────────────────────────────────────────────────────

    if (cmd == "PING") {
        return SuccessResponse("pong");
    }

    if (cmd == "INFO") {
        char proc_name[MAX_PATH] = {0};
        GetModuleFileNameA(NULL, proc_name, MAX_PATH);
        char* slash = strrchr(proc_name, '\\');
        std::string name = slash ? slash + 1 : proc_name;

        return Response()
            .add("status", "ok")
            .add("process", name)
            .add("pid", (int64_t)g_pid)
            .addHex("base_address", g_base_address)
            .add("architecture", "x64")
            .build();
    }

    // ── Memory ───────────────────────────────────────────────────────

    if (cmd == "READ") {
        if (tokens.size() < 3) return ErrorResponse("usage: READ <addr_hex> <size>");
        return CmdRead(ParseAddr(tokens[1]), ParseInt(tokens[2]));
    }

    if (cmd == "WRITE") {
        if (tokens.size() < 3) return ErrorResponse("usage: WRITE <addr_hex> <hex_bytes>");
        return CmdWrite(ParseAddr(tokens[1]), JoinFrom(tokens, 2));
    }

    if (cmd == "READPTR") {
        if (tokens.size() < 2) return ErrorResponse("usage: READPTR <addr_hex> [depth]");
        int depth = tokens.size() >= 3 ? ParseInt(tokens[2], 4) : 4;
        return CmdReadPtr(ParseAddr(tokens[1]), depth);
    }

    if (cmd == "PROTECT") {
        if (tokens.size() < 2) return ErrorResponse("usage: PROTECT <addr_hex>");
        return CmdProtect(ParseAddr(tokens[1]));
    }

    if (cmd == "ALLOC") {
        if (tokens.size() < 2) return ErrorResponse("usage: ALLOC <size> [protect_hex]");
        DWORD prot = tokens.size() >= 3 ? (DWORD)ParseAddr(tokens[2]) : PAGE_EXECUTE_READWRITE;
        return CmdAlloc(ParseInt(tokens[1]), prot);
    }

    if (cmd == "FREE") {
        if (tokens.size() < 2) return ErrorResponse("usage: FREE <addr_hex>");
        return CmdFree(ParseAddr(tokens[1]));
    }

    if (cmd == "FILL") {
        if (tokens.size() < 4) return ErrorResponse("usage: FILL <addr_hex> <size> <byte_hex>");
        return CmdFill(ParseAddr(tokens[1]), ParseInt(tokens[2]), (uint8_t)ParseAddr(tokens[3]));
    }

    // ── Disassembly ──────────────────────────────────────────────────

    if (cmd == "DISASM") {
        if (tokens.size() < 2) return ErrorResponse("usage: DISASM <addr_hex> [count]");
        int count = tokens.size() >= 3 ? ParseInt(tokens[2], 10) : 10;
        return CmdDisasm(ParseAddr(tokens[1]), count);
    }

    if (cmd == "DISASM_FUNC") {
        if (tokens.size() < 2) return ErrorResponse("usage: DISASM_FUNC <addr_hex>");
        return CmdDisasmFunc(ParseAddr(tokens[1]));
    }

    // ── Scanning ─────────────────────────────────────────────────────

    if (cmd == "SCAN") {
        if (tokens.size() < 4) return ErrorResponse("usage: SCAN <start_hex> <size_hex> <pattern>");
        return CmdScan(ParseAddr(tokens[1]), (size_t)ParseAddr(tokens[2]), JoinFrom(tokens, 3));
    }

    if (cmd == "SCAN_ALL") {
        if (tokens.size() < 4) return ErrorResponse("usage: SCAN_ALL <start_hex> <size_hex> <pattern> [max]");
        // Find the max_results arg — it's tricky because pattern has spaces
        // Convention: last token if it's purely numeric is max_results
        // Otherwise default to 256
        return CmdScanAll(ParseAddr(tokens[1]), (size_t)ParseAddr(tokens[2]),
                          JoinFrom(tokens, 3), MCP_MAX_SCAN_RESULTS);
    }

    if (cmd == "STRINGS") {
        if (tokens.size() < 3) return ErrorResponse("usage: STRINGS <start_hex> <size_hex> [min_len]");
        int min_len = tokens.size() >= 4 ? ParseInt(tokens[3], 4) : 4;
        return CmdStrings(ParseAddr(tokens[1]), (size_t)ParseAddr(tokens[2]), min_len);
    }

    if (cmd == "FIND_STR") {
        if (tokens.size() < 4) return ErrorResponse("usage: FIND_STR <start_hex> <size_hex> <string>");
        return CmdFindStr(ParseAddr(tokens[1]), (size_t)ParseAddr(tokens[2]), JoinFrom(tokens, 3));
    }

    // ── Breakpoints ──────────────────────────────────────────────────

    if (cmd == "BP" || cmd == "BP_SET") {
        if (tokens.size() < 2) return ErrorResponse("usage: BP <addr_hex>");
        return CmdBpSet(ParseAddr(tokens[1]));
    }

    if (cmd == "BP_DEL") {
        if (tokens.size() < 2) return ErrorResponse("usage: BP_DEL <addr_hex>");
        return CmdBpDel(ParseAddr(tokens[1]));
    }

    if (cmd == "BP_DEL_ALL") {
        // Remove all breakpoints by reading the list and deleting each one in a loop
        int removed = 0;
        static const std::string TAG = "\"address\":\"0x";
        for (int attempt = 0; attempt < MCP_MAX_BREAKPOINTS; attempt++) {
            std::string cur = CmdBpList();
            size_t pos = cur.find(TAG);
            if (pos == std::string::npos) break;          // no breakpoints left
            pos += TAG.size();                             // now points just after "0x"
            size_t end = cur.find("\"", pos);
            if (end == std::string::npos) break;
            std::string hex_digits = cur.substr(pos, end - pos); // e.g. "7FF6C8691050"
            uint64_t addr = strtoull(hex_digits.c_str(), nullptr, 16);
            if (addr == 0) break;
            CmdBpDel(addr);
            removed++;
        }
        return Response()
            .add("status", "ok")
            .add("removed", (int64_t)removed)
            .build();
    }

    if (cmd == "BP_LIST") {
        return CmdBpList();
    }

    if (cmd == "BP_CTX") {
        if (tokens.size() < 2) return ErrorResponse("usage: BP_CTX <addr_hex>");
        return CmdBpCtx(ParseAddr(tokens[1]));
    }

    if (cmd == "BP_WAIT") {
        if (tokens.size() < 2) return ErrorResponse("usage: BP_WAIT <addr_hex> [timeout_ms]");
        DWORD timeout = tokens.size() >= 3 ? (DWORD)ParseInt(tokens[2], 10000) : 10000;
        return CmdBpWait(ParseAddr(tokens[1]), timeout);
    }

    if (cmd == "BP_ENABLE") {
        if (tokens.size() < 2) return ErrorResponse("usage: BP_ENABLE <addr_hex>");
        return CmdBpEnable(ParseAddr(tokens[1]));
    }

    if (cmd == "BP_DISABLE") {
        if (tokens.size() < 2) return ErrorResponse("usage: BP_DISABLE <addr_hex>");
        return CmdBpDisable(ParseAddr(tokens[1]));
    }

    // ── Threads ──────────────────────────────────────────────────────

    if (cmd == "THREADS") {
        return CmdThreads();
    }

    if (cmd == "THREAD_CTX") {
        if (tokens.size() < 2) return ErrorResponse("usage: THREAD_CTX <thread_id>");
        return CmdThreadCtx((DWORD)ParseInt(tokens[1]));
    }

    if (cmd == "THREAD_SET") {
        if (tokens.size() < 4) return ErrorResponse("usage: THREAD_SET <thread_id> <register> <value_hex>");
        return CmdThreadSet((DWORD)ParseInt(tokens[1]), tokens[2], ParseAddr(tokens[3]));
    }

    if (cmd == "THREAD_SUSPEND") {
        if (tokens.size() < 2) return ErrorResponse("usage: THREAD_SUSPEND <thread_id>");
        return CmdThreadSuspend((DWORD)ParseInt(tokens[1]));
    }

    if (cmd == "THREAD_RESUME") {
        if (tokens.size() < 2) return ErrorResponse("usage: THREAD_RESUME <thread_id>");
        return CmdThreadResume((DWORD)ParseInt(tokens[1]));
    }

    if (cmd == "CALLSTACK") {
        if (tokens.size() < 2) return ErrorResponse("usage: CALLSTACK <thread_id>");
        return CmdCallStack((DWORD)ParseInt(tokens[1]));
    }

    // ── Modules ──────────────────────────────────────────────────────

    if (cmd == "MODULES") {
        return CmdModules();
    }

    if (cmd == "EXPORTS") {
        if (tokens.size() < 2) return ErrorResponse("usage: EXPORTS <module_name>");
        return CmdExports(tokens[1]);
    }

    if (cmd == "IMPORTS") {
        if (tokens.size() < 2) return ErrorResponse("usage: IMPORTS <module_name>");
        return CmdImports(tokens[1]);
    }

    if (cmd == "SECTIONS") {
        if (tokens.size() < 2) return ErrorResponse("usage: SECTIONS <module_name>");
        return CmdSections(tokens[1]);
    }

    // ── Hooks ────────────────────────────────────────────────────────

    if (cmd == "HOOK") {
        if (tokens.size() < 2) return ErrorResponse("usage: HOOK <addr_hex> [name]  OR  HOOK <module.dll> <FunctionName>");
        // Detect module+function form: if token[1] contains a dot and doesn't start with 0x
        bool is_module_func = (tokens.size() >= 3 &&
                               tokens[1].find('.') != std::string::npos &&
                               tokens[1].substr(0, 2) != "0x" &&
                               tokens[1].substr(0, 2) != "0X");
        if (is_module_func) {
            HMODULE hMod = GetModuleHandleA(tokens[1].c_str());
            if (!hMod) hMod = LoadLibraryA(tokens[1].c_str());
            if (!hMod) return ErrorResponse("module not found: " + tokens[1]);
            FARPROC fn = GetProcAddress(hMod, tokens[2].c_str());
            if (!fn) return ErrorResponse("function not found: " + tokens[2] + " in " + tokens[1]);
            std::string name = tokens[1] + "!" + tokens[2];
            return CmdHook((uint64_t)fn, name);
        }
        std::string name = tokens.size() >= 3 ? JoinFrom(tokens, 2) : "";
        return CmdHook(ParseAddr(tokens[1]), name);
    }

    if (cmd == "UNHOOK") {
        if (tokens.size() < 2) return ErrorResponse("usage: UNHOOK <addr_hex>  OR  UNHOOK <module.dll> <FunctionName>");
        bool is_module_func = (tokens.size() >= 3 &&
                               tokens[1].find('.') != std::string::npos &&
                               tokens[1].substr(0, 2) != "0x" &&
                               tokens[1].substr(0, 2) != "0X");
        if (is_module_func) {
            HMODULE hMod = GetModuleHandleA(tokens[1].c_str());
            if (!hMod) return ErrorResponse("module not found: " + tokens[1]);
            FARPROC fn = GetProcAddress(hMod, tokens[2].c_str());
            if (!fn) return ErrorResponse("function not found: " + tokens[2] + " in " + tokens[1]);
            return CmdUnhook((uint64_t)fn);
        }
        return CmdUnhook(ParseAddr(tokens[1]));
    }

    if (cmd == "HOOK_LIST") {
        return CmdHookList();
    }

    if (cmd == "HOOK_LOG") {
        if (tokens.size() < 2) return ErrorResponse("usage: HOOK_LOG <addr_hex> [count]");
        int count = tokens.size() >= 3 ? ParseInt(tokens[2], 64) : 64;
        return CmdHookLog(ParseAddr(tokens[1]), count);
    }

    // ── Heap ─────────────────────────────────────────────────────────

    if (cmd == "HEAPS") {
        return CmdHeaps();
    }

    if (cmd == "HEAP_WALK") {
        if (tokens.size() < 2) return ErrorResponse("usage: HEAP_WALK <heap_id_hex> [max_entries]");
        int max = tokens.size() >= 3 ? ParseInt(tokens[2], 100) : 100;
        return CmdHeapWalk(ParseAddr(tokens[1]), max);
    }

    // ── Stealth / Anti-Anti-Debug ───────────────────────────────────

    if (cmd == "STEALTH_ON") {
        int level = tokens.size() >= 2 ? ParseInt(tokens[1], 2) : 2;
        return CmdStealthOn(level);
    }

    if (cmd == "STEALTH_OFF") {
        return CmdStealthOff();
    }

    if (cmd == "STEALTH_STATUS") {
        return CmdStealthStatus();
    }

    if (cmd == "STEALTH_PATCH_PEB") {
        return CmdStealthPatchPEB();
    }

    if (cmd == "STEALTH_HIDE") {
        return CmdStealthHideModule();
    }

    if (cmd == "STEALTH_UNHIDE") {
        return CmdStealthUnhideModule();
    }

    // ── Help ─────────────────────────────────────────────────────────

    if (cmd == "HELP") {
        std::vector<std::string> cmds = {
            "PING", "INFO",
            "READ <addr> <size>", "WRITE <addr> <hex>", "READPTR <addr> [depth]",
            "PROTECT <addr>", "ALLOC <size>", "FREE <addr>", "FILL <addr> <size> <byte>",
            "DISASM <addr> [count]", "DISASM_FUNC <addr>",
            "SCAN <start> <size> <pattern>", "SCAN_ALL <start> <size> <pattern>",
            "STRINGS <start> <size> [min_len]", "FIND_STR <start> <size> <string>",
            "BP <addr>", "BP_SET <addr>", "BP_DEL <addr>", "BP_DEL_ALL", "BP_LIST", "BP_CTX <addr>",
            "BP_WAIT <addr> [timeout]", "BP_ENABLE <addr>", "BP_DISABLE <addr>",
            "THREADS", "THREAD_CTX <tid>", "THREAD_SET <tid> <reg> <val>",
            "THREAD_SUSPEND <tid>", "THREAD_RESUME <tid>", "CALLSTACK <tid>",
            "MODULES", "EXPORTS <module>", "IMPORTS <module>", "SECTIONS <module>",
            "HOOK <addr> [name]", "HOOK <module.dll> <Function>", "UNHOOK <addr>", "UNHOOK <module.dll> <Function>", "HOOK_LIST", "HOOK_LOG <addr> [count]",
            "HEAPS", "HEAP_WALK <heap_id> [max]",
            "STEALTH_ON [level]", "STEALTH_OFF", "STEALTH_STATUS",
            "STEALTH_PATCH_PEB", "STEALTH_HIDE", "STEALTH_UNHIDE",
            "HELP"
        };
        return Response()
            .add("status", "ok")
            .addArray("commands", cmds)
            .build();
    }

    return ErrorResponse("unknown command: " + tokens[0] + " (try HELP)");
}
