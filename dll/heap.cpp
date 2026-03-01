#include "heap.h"
#include "response.h"
#include <windows.h>
#include <tlhelp32.h>
#include <vector>

std::string CmdHeaps() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, g_pid);
    if (snap == INVALID_HANDLE_VALUE)
        return ErrorResponse("CreateToolhelp32Snapshot failed");

    HEAPLIST32 hl;
    hl.dwSize = sizeof(hl);

    std::vector<std::string> heaps;

    if (Heap32ListFirst(snap, &hl)) {
        do {
            std::string flags_str;
            if (hl.dwFlags & HF32_DEFAULT) flags_str += "DEFAULT ";
            if (hl.dwFlags & HF32_SHARED)  flags_str += "SHARED ";
            if (flags_str.empty()) flags_str = "NONE";

            heaps.push_back(
                Response()
                    .addHex("heap_id", hl.th32HeapID)
                    .add("flags", flags_str)
                    .build()
            );
        } while (Heap32ListNext(snap, &hl));
    }

    CloseHandle(snap);

    return Response()
        .add("status", "ok")
        .add("count", (int64_t)heaps.size())
        .addRawArray("heaps", heaps)
        .build();
}

std::string CmdHeapWalk(uint64_t heap_id, int max_entries) {
    if (max_entries <= 0) max_entries = 100;
    if (max_entries > 1000) max_entries = 1000;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, g_pid);
    if (snap == INVALID_HANDLE_VALUE)
        return ErrorResponse("CreateToolhelp32Snapshot failed");

    HEAPLIST32 hl;
    hl.dwSize = sizeof(hl);

    bool found = false;
    if (Heap32ListFirst(snap, &hl)) {
        do {
            if (hl.th32HeapID == (ULONG_PTR)heap_id) {
                found = true;
                break;
            }
        } while (Heap32ListNext(snap, &hl));
    }

    if (!found) {
        CloseHandle(snap);
        return ErrorResponse("heap not found");
    }

    HEAPENTRY32 he;
    he.dwSize = sizeof(he);

    std::vector<std::string> entries;
    uint64_t total_size = 0;

    if (Heap32First(&he, g_pid, hl.th32HeapID)) {
        do {
            if ((int)entries.size() >= max_entries) break;

            std::string flags_str;
            if (he.dwFlags & LF32_FIXED)    flags_str += "FIXED ";
            if (he.dwFlags & LF32_FREE)     flags_str += "FREE ";
            if (he.dwFlags & LF32_MOVEABLE) flags_str += "MOVEABLE ";

            entries.push_back(
                Response()
                    .addHex("address", he.dwAddress)
                    .addHex("block_size", he.dwBlockSize)
                    .add("flags", flags_str)
                    .build()
            );

            total_size += he.dwBlockSize;
        } while (Heap32Next(&he));
    }

    CloseHandle(snap);

    return Response()
        .add("status", "ok")
        .addHex("heap_id", heap_id)
        .add("count", (int64_t)entries.size())
        .addHex("total_size", total_size)
        .addRawArray("entries", entries)
        .build();
}
