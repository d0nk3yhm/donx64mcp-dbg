#include "modules.h"
#include "memory_ops.h"
#include "response.h"
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <cstdio>
#include <algorithm>

// ── List all loaded modules ─────────────────────────────────────────────

std::string CmdModules() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, g_pid);
    if (snap == INVALID_HANDLE_VALUE)
        return ErrorResponse("CreateToolhelp32Snapshot failed");

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);

    std::vector<std::string> modules;

    if (Module32FirstW(snap, &me)) {
        do {
            // Convert wide name to narrow
            char name[MAX_MODULE_NAME32 + 1];
            char path[MAX_PATH + 1];
            WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, name, sizeof(name), NULL, NULL);
            WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1, path, sizeof(path), NULL, NULL);

            modules.push_back(
                Response()
                    .add("name", std::string(name))
                    .addHex("base", (uint64_t)me.modBaseAddr)
                    .addHex("size", (uint64_t)me.modBaseSize)
                    .add("path", std::string(path))
                    .build()
            );
        } while (Module32NextW(snap, &me));
    }

    CloseHandle(snap);

    return Response()
        .add("status", "ok")
        .add("count", (int64_t)modules.size())
        .addRawArray("modules", modules)
        .build();
}

// ── Helper: find module base by name ────────────────────────────────────

static HMODULE FindModuleByName(const std::string& name) {
    // Try direct load first
    HMODULE h = GetModuleHandleA(name.c_str());
    if (h) return h;

    // Try with .dll extension
    std::string with_ext = name + ".dll";
    h = GetModuleHandleA(with_ext.c_str());
    if (h) return h;

    // Case-insensitive search via toolhelp
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, g_pid);
    if (snap == INVALID_HANDLE_VALUE) return NULL;

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);

    std::string lower_name = name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);

    HMODULE result = NULL;
    if (Module32FirstW(snap, &me)) {
        do {
            char mod_name[MAX_MODULE_NAME32 + 1];
            WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, mod_name, sizeof(mod_name), NULL, NULL);
            std::string mod_lower(mod_name);
            std::transform(mod_lower.begin(), mod_lower.end(), mod_lower.begin(), ::tolower);

            if (mod_lower == lower_name || mod_lower == lower_name + ".dll") {
                result = (HMODULE)me.modBaseAddr;
                break;
            }
        } while (Module32NextW(snap, &me));
    }

    CloseHandle(snap);
    return result;
}

// ── List exports of a module ────────────────────────────────────────────

std::string CmdExports(const std::string& module_name) {
    HMODULE hMod = FindModuleByName(module_name);
    if (!hMod)
        return ErrorResponse("module not found: " + module_name);

    uint64_t base = (uint64_t)hMod;

    // Parse PE export directory
    IMAGE_DOS_HEADER dos;
    if (!MemReadSafe((void*)base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return ErrorResponse("invalid DOS header");

    IMAGE_NT_HEADERS64 nt;
    if (!MemReadSafe((void*)(base + dos.e_lfanew), &nt, sizeof(nt)))
        return ErrorResponse("failed to read NT headers");

    DWORD export_rva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD export_size = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if (export_rva == 0)
        return Response().add("status", "ok").add("count", (int64_t)0)
               .addRawArray("exports", {}).build();

    IMAGE_EXPORT_DIRECTORY exp_dir;
    if (!MemReadSafe((void*)(base + export_rva), &exp_dir, sizeof(exp_dir)))
        return ErrorResponse("failed to read export directory");

    std::vector<std::string> exports;
    int max_exports = 1000;

    // Read function RVA array
    std::vector<DWORD> func_rvas(exp_dir.NumberOfFunctions);
    if (exp_dir.NumberOfFunctions > 0) {
        MemReadSafe((void*)(base + exp_dir.AddressOfFunctions),
                    func_rvas.data(), func_rvas.size() * sizeof(DWORD));
    }

    // Read name RVA array and ordinal array
    std::vector<DWORD> name_rvas(exp_dir.NumberOfNames);
    std::vector<WORD> ordinals(exp_dir.NumberOfNames);
    if (exp_dir.NumberOfNames > 0) {
        MemReadSafe((void*)(base + exp_dir.AddressOfNames),
                    name_rvas.data(), name_rvas.size() * sizeof(DWORD));
        MemReadSafe((void*)(base + exp_dir.AddressOfNameOrdinals),
                    ordinals.data(), ordinals.size() * sizeof(WORD));
    }

    for (DWORD i = 0; i < exp_dir.NumberOfNames && (int)exports.size() < max_exports; i++) {
        char func_name[256] = {0};
        MemReadSafe((void*)(base + name_rvas[i]), func_name, sizeof(func_name) - 1);

        WORD ord = ordinals[i];
        DWORD func_rva = (ord < func_rvas.size()) ? func_rvas[ord] : 0;

        exports.push_back(
            Response()
                .add("name", std::string(func_name))
                .add("ordinal", (int64_t)(ord + exp_dir.Base))
                .addHex("rva", func_rva)
                .addHex("address", base + func_rva)
                .build()
        );
    }

    return Response()
        .add("status", "ok")
        .add("module", module_name)
        .add("count", (int64_t)exports.size())
        .addRawArray("exports", exports)
        .build();
}

// ── List imports of a module ────────────────────────────────────────────

std::string CmdImports(const std::string& module_name) {
    HMODULE hMod = FindModuleByName(module_name);
    if (!hMod)
        return ErrorResponse("module not found: " + module_name);

    uint64_t base = (uint64_t)hMod;

    IMAGE_DOS_HEADER dos;
    if (!MemReadSafe((void*)base, &dos, sizeof(dos)))
        return ErrorResponse("invalid DOS header");

    IMAGE_NT_HEADERS64 nt;
    if (!MemReadSafe((void*)(base + dos.e_lfanew), &nt, sizeof(nt)))
        return ErrorResponse("failed to read NT headers");

    DWORD import_rva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (import_rva == 0)
        return Response().add("status", "ok").add("count", (int64_t)0)
               .addRawArray("imports", {}).build();

    std::vector<std::string> imports;
    int max_imports = 2000;
    uint64_t desc_addr = base + import_rva;

    for (int d = 0; d < 256; d++) {
        IMAGE_IMPORT_DESCRIPTOR desc;
        if (!MemReadSafe((void*)(desc_addr + d * sizeof(desc)), &desc, sizeof(desc)))
            break;
        if (desc.Name == 0) break; // Terminator

        char dll_name[256] = {0};
        MemReadSafe((void*)(base + desc.Name), dll_name, sizeof(dll_name) - 1);

        // Walk the IAT
        uint64_t thunk_addr = base + (desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk);
        uint64_t iat_addr = base + desc.FirstThunk;

        for (int t = 0; t < 4096 && (int)imports.size() < max_imports; t++) {
            uint64_t thunk_data = 0;
            if (!MemReadSafe((void*)(thunk_addr + t * 8), &thunk_data, 8))
                break;
            if (thunk_data == 0) break;

            uint64_t resolved = 0;
            MemReadSafe((void*)(iat_addr + t * 8), &resolved, 8);

            std::string func_name;
            if (thunk_data & (1ULL << 63)) {
                // Import by ordinal
                func_name = "Ordinal_" + std::to_string(thunk_data & 0xFFFF);
            } else {
                char name_buf[256] = {0};
                // Skip the 2-byte hint
                MemReadSafe((void*)(base + thunk_data + 2), name_buf, sizeof(name_buf) - 1);
                func_name = name_buf;
            }

            imports.push_back(
                Response()
                    .add("dll", std::string(dll_name))
                    .add("function", func_name)
                    .addHex("iat_address", iat_addr + t * 8)
                    .addHex("resolved", resolved)
                    .build()
            );
        }
    }

    return Response()
        .add("status", "ok")
        .add("module", module_name)
        .add("count", (int64_t)imports.size())
        .addRawArray("imports", imports)
        .build();
}

// ── List PE sections ────────────────────────────────────────────────────

std::string CmdSections(const std::string& module_name) {
    HMODULE hMod = FindModuleByName(module_name);
    if (!hMod)
        return ErrorResponse("module not found: " + module_name);

    uint64_t base = (uint64_t)hMod;

    IMAGE_DOS_HEADER dos;
    if (!MemReadSafe((void*)base, &dos, sizeof(dos)))
        return ErrorResponse("invalid DOS header");

    IMAGE_NT_HEADERS64 nt;
    if (!MemReadSafe((void*)(base + dos.e_lfanew), &nt, sizeof(nt)))
        return ErrorResponse("failed to read NT headers");

    int num_sections = nt.FileHeader.NumberOfSections;
    uint64_t section_addr = base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);

    std::vector<std::string> sections;

    for (int i = 0; i < num_sections; i++) {
        IMAGE_SECTION_HEADER sec;
        if (!MemReadSafe((void*)(section_addr + i * sizeof(sec)), &sec, sizeof(sec)))
            break;

        char name[9] = {0};
        memcpy(name, sec.Name, 8);

        auto chars_str = [](DWORD c) -> std::string {
            std::string s;
            if (c & IMAGE_SCN_MEM_EXECUTE) s += "X";
            if (c & IMAGE_SCN_MEM_READ)    s += "R";
            if (c & IMAGE_SCN_MEM_WRITE)   s += "W";
            if (c & IMAGE_SCN_CNT_CODE)    s += " CODE";
            if (c & IMAGE_SCN_CNT_INITIALIZED_DATA)   s += " IDATA";
            if (c & IMAGE_SCN_CNT_UNINITIALIZED_DATA) s += " UDATA";
            return s;
        };

        sections.push_back(
            Response()
                .add("name", std::string(name))
                .addHex("virtual_address", base + sec.VirtualAddress)
                .addHex("virtual_size", sec.Misc.VirtualSize)
                .addHex("raw_size", sec.SizeOfRawData)
                .add("characteristics", chars_str(sec.Characteristics))
                .build()
        );
    }

    return Response()
        .add("status", "ok")
        .add("module", module_name)
        .add("count", (int64_t)sections.size())
        .addRawArray("sections", sections)
        .build();
}
