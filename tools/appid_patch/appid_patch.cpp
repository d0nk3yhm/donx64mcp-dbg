// appid_patch.exe
//
// Finds and optionally patches a Steam AppID literal embedded in a managed
// .NET assembly's IL (e.g. Assembly-CSharp.dll from a Unity/Steamworks game).
//
// The pattern this looks for is exactly what a C# call like
//     new AppId_t(4001890)
// or
//     SteamAPI.RestartAppIfNecessary(4001890)
// compiles down to: the IL opcode ldc.i4 (0x20, a 4-byte little-endian int32
// literal) immediately followed by either newobj (0x73) or a call/callvirt
// (0x28/0x6F) - each taking a 4-byte metadata token. That instruction pair is
// how a C# integer constant reaches native code as a "magic number", and it
// is stable across obfuscation levels that don't touch IL (the vast majority
// of Unity/Mono builds ship IL essentially as the compiler emitted it).
//
// This does NOT do full CLR metadata table parsing (no #~ stream, no token
// resolution to a type/method name) - that would let it name which
// method/type each newobj resolves to, but this tool's job is narrower: find
// candidate int32 literals that could plausibly be a Steam AppID, so a human
// (or the model driving this tool) can point at the right one and patch it.
// A real AppID is a small positive integer (Valve has been handing them out
// since 2003; the space is nowhere near 2^31), so filtering the range catches
// the overwhelming majority of false positives (loop bounds, buffer sizes,
// hashes) without needing to resolve any tokens at all.
//
// Usage:
//   appid_patch.exe <Assembly-CSharp.dll>                       list candidates
//   appid_patch.exe <dll> --min N --max N                       list, custom range
//   appid_patch.exe <dll> --patch NEWVALUE --at 0xOFFSET         patch one exact spot
//   appid_patch.exe <dll> --patch NEWVALUE --auto                patch iff exactly one
//                                                                 candidate in range
//   appid_patch.exe <dll> --patch NEWVALUE --auto --value OLD    patch iff exactly one
//                                                                 candidate equals OLD
//
// A patch always writes a ".bak" of the original file first (refusing to
// overwrite an existing .bak, so re-running never destroys the true original),
// then edits the 4 literal bytes in place and reports old -> new.

#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <optional>
#include <algorithm>

// ---------------------------------------------------------------- PE/COR20

#pragma pack(push, 1)
struct IMAGE_COR20_HEADER_MIN {
    uint32_t cb;
    uint16_t MajorRuntimeVersion;
    uint16_t MinorRuntimeVersion;
    IMAGE_DATA_DIRECTORY MetaData;
    uint32_t Flags;
    uint32_t EntryPointToken;
    IMAGE_DATA_DIRECTORY Resources;
    IMAGE_DATA_DIRECTORY StrongNameSignature;
    IMAGE_DATA_DIRECTORY CodeManagerTable;
    IMAGE_DATA_DIRECTORY VTableFixups;
    IMAGE_DATA_DIRECTORY ExportAddressTableJumps;
    IMAGE_DATA_DIRECTORY ManagedNativeHeader;
};
#pragma pack(pop)

struct Section { std::string name; uint32_t va; uint32_t vsize; uint32_t rawoff; uint32_t rawsize; };

struct PeInfo {
    bool ok = false;
    bool isDotNet = false;
    uint32_t textVa = 0, textRaw = 0, textSize = 0;   // the .text section, RVA + file offset
    std::vector<Section> sections;
    std::string error;
};

static uint32_t RvaToFileOffset(const PeInfo& pe, uint32_t rva) {
    for (auto& s : pe.sections) {
        if (rva >= s.va && rva < s.va + s.vsize) return s.rawoff + (rva - s.va);
    }
    return 0;
}

static PeInfo ParsePe(const std::vector<uint8_t>& data) {
    PeInfo pe;
    if (data.size() < 0x400) { pe.error = "file too small to be a PE"; return pe; }
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { pe.error = "not a PE (bad DOS signature)"; return pe; }
    uint32_t peOff = dos->e_lfanew;
    if (peOff + sizeof(IMAGE_NT_HEADERS64) > data.size()) { pe.error = "PE header out of range"; return pe; }
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(data.data() + peOff);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { pe.error = "not a PE (bad NT signature)"; return pe; }
    bool is64 = nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    uint32_t numSections = nt->FileHeader.NumberOfSections;
    uint32_t sectionsOff = peOff + 4 + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader;

    for (uint32_t i = 0; i < numSections; i++) {
        auto sh = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            data.data() + sectionsOff + i * sizeof(IMAGE_SECTION_HEADER));
        char name[9] = {0};
        memcpy(name, sh->Name, 8);
        Section s{ name, sh->VirtualAddress, sh->Misc.VirtualSize, sh->PointerToRawData, sh->SizeOfRawData };
        pe.sections.push_back(s);
        if (_stricmp(name, ".text") == 0) {
            pe.textVa = s.va; pe.textRaw = s.rawoff; pe.textSize = s.vsize;
        }
    }

    // CLR header lives in data directory #14 (COM_DESCRIPTOR)
    uint32_t clrRva = 0, clrSize = 0;
    if (is64) {
        auto opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(&nt->OptionalHeader);
        if (opt->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
            clrRva = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
            clrSize = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;
        }
    } else {
        auto opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(&nt->OptionalHeader);
        if (opt->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
            clrRva = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
            clrSize = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;
        }
    }
    pe.isDotNet = (clrRva != 0 && clrSize >= sizeof(IMAGE_COR20_HEADER_MIN));
    pe.ok = true;
    return pe;
}

// ------------------------------------------------------------- IL scanning

struct Candidate {
    uint32_t fileOffset;      // offset of the ldc.i4 opcode byte
    int32_t  value;           // the literal int32
    uint8_t  followOp;        // 0x73 newobj, 0x28 call, 0x6F callvirt
    uint32_t token;           // the 4-byte metadata token that follows
    const char* tokenTable;   // human label for the token's high byte
};

static const char* TokenTableName(uint32_t token) {
    switch (token >> 24) {
        case 0x06: return "MethodDef";
        case 0x0A: return "MemberRef";
        case 0x2B: return "MethodSpec";
        default:   return "?";
    }
}

// ldc.i4 = 0x20 (5 bytes: opcode + int32). The short forms (ldc.i4.s, ldc.i4.0..8)
// only cover -1..8 and one signed byte, both far outside any real AppID range, so
// they are deliberately not matched here - a real AppID never compiles to them.
static std::vector<Candidate> Scan(const std::vector<uint8_t>& data, uint32_t start,
                                    uint32_t end, int64_t minVal, int64_t maxVal) {
    std::vector<Candidate> out;
    if (end > data.size()) end = (uint32_t)data.size();
    for (uint32_t i = start; i + 10 <= end; i++) {
        if (data[i] != 0x20) continue;                 // ldc.i4
        int32_t val;
        memcpy(&val, &data[i + 1], 4);
        if (val < minVal || val > maxVal) continue;
        uint8_t follow = data[i + 5];
        if (follow != 0x73 && follow != 0x28 && follow != 0x6F) continue; // newobj/call/callvirt
        uint32_t token;
        memcpy(&token, &data[i + 6], 4);
        Candidate c{ i, val, follow, token, TokenTableName(token) };
        out.push_back(c);
    }
    return out;
}

static const char* OpName(uint8_t op) {
    switch (op) { case 0x73: return "newobj"; case 0x28: return "call"; case 0x6F: return "callvirt"; }
    return "?";
}

// --------------------------------------------------------------------- main

static void Usage(const char* argv0) {
    printf(
        "appid_patch - find/patch a Steam AppID literal in a .NET assembly's IL\n\n"
        "Usage:\n"
        "  %s <dll>                                 list AppID-shaped candidates\n"
        "  %s <dll> --min N --max N                 list, with a custom plausible range\n"
        "  %s <dll> --patch NEWVALUE --at 0xOFFSET   patch the literal at an exact file offset\n"
        "  %s <dll> --patch NEWVALUE --auto          patch iff exactly one candidate matches\n"
        "  %s <dll> --patch NEWVALUE --auto --value OLD   ...and its value is exactly OLD\n\n"
        "Always writes <dll>.bak (once; refuses to overwrite an existing one) before patching.\n",
        argv0, argv0, argv0, argv0, argv0);
}

int main(int argc, char** argv) {
    if (argc < 2) { Usage(argv[0]); return 1; }
    std::string path = argv[1];
    int64_t minVal = 1, maxVal = 5000000;   // Valve's AppID space so far; override with --min/--max
    std::optional<int32_t> patchTo;
    std::optional<uint32_t> atOffset;
    std::optional<int64_t> requireOldValue;
    bool autoMode = false;

    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&](const char* name) -> std::string {
            if (i + 1 >= argc) { fprintf(stderr, "%s needs a value\n", name); exit(2); }
            return argv[++i];
        };
        if (a == "--min") minVal = _atoi64(next("--min").c_str());
        else if (a == "--max") maxVal = _atoi64(next("--max").c_str());
        else if (a == "--patch") patchTo = (int32_t)_atoi64(next("--patch").c_str());
        else if (a == "--at") atOffset = (uint32_t)strtoul(next("--at").c_str(), nullptr, 0);
        else if (a == "--auto") autoMode = true;
        else if (a == "--value") requireOldValue = _atoi64(next("--value").c_str());
        else { fprintf(stderr, "unknown argument: %s\n", a.c_str()); Usage(argv[0]); return 2; }
    }

    FILE* f = nullptr;
    fopen_s(&f, path.c_str(), "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path.c_str()); return 3; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> data(sz);
    fread(data.data(), 1, sz, f);
    fclose(f);

    PeInfo pe = ParsePe(data);
    if (!pe.ok) { fprintf(stderr, "PE parse failed: %s\n", pe.error.c_str()); return 4; }
    if (!pe.isDotNet) {
        fprintf(stderr, "warning: no CLR header found - this may not be a managed assembly; "
                        "matches below are a raw byte-pattern scan of .text, not IL-verified.\n");
    }
    printf("%s: %ld bytes, %s, .text at file offset 0x%X (0x%X bytes)\n",
           path.c_str(), sz, pe.isDotNet ? ".NET assembly (CLR header present)" : "NOT a .NET assembly",
           pe.textRaw, pe.textSize);

    uint32_t scanStart = pe.textRaw ? pe.textRaw : 0;
    uint32_t scanEnd = pe.textRaw ? pe.textRaw + pe.textSize : (uint32_t)data.size();
    auto candidates = Scan(data, scanStart, scanEnd, minVal, maxVal);

    printf("\n%zu candidate literal(s) in [%lld, %lld] immediately followed by newobj/call/callvirt:\n",
           candidates.size(), (long long)minVal, (long long)maxVal);
    for (auto& c : candidates) {
        printf("  file offset 0x%08X : ldc.i4 %-10d  %s  token 0x%08X (%s)\n",
               c.fileOffset, c.value, OpName(c.followOp), c.token, c.tokenTable);
    }

    if (!patchTo) {
        if (!candidates.empty())
            printf("\nTo patch one, re-run with --patch 480 --at 0x%X\n"
                   "(or --patch 480 --auto if this offset list has exactly one hit you trust)\n",
                   candidates[0].fileOffset);
        return 0;
    }

    // ---- patch mode ----
    uint32_t target;
    if (atOffset) {
        target = *atOffset;
        bool found = false;
        for (auto& c : candidates) if (c.fileOffset == target) { found = true; break; }
        if (!found) {
            fprintf(stderr, "0x%X is not one of the candidates listed above (or is outside .text) "
                            "- refusing to patch a location this tool didn't itself identify as "
                            "ldc.i4+newobj/call/callvirt.\n", target);
            return 5;
        }
    } else if (autoMode) {
        std::vector<Candidate> pool = candidates;
        if (requireOldValue) {
            std::vector<Candidate> filtered;
            for (auto& c : pool) if (c.value == *requireOldValue) filtered.push_back(c);
            pool = filtered;
        }
        if (pool.size() != 1) {
            fprintf(stderr, "--auto requires exactly one candidate; found %zu%s. "
                            "Use --at 0xOFFSET to pick one explicitly.\n",
                    pool.size(), requireOldValue ? " matching --value" : "");
            return 6;
        }
        target = pool[0].fileOffset;
    } else {
        fprintf(stderr, "--patch needs either --at 0xOFFSET or --auto\n");
        return 2;
    }

    int32_t oldValue;
    memcpy(&oldValue, &data[target + 1], 4);

    std::string bak = path + ".bak";
    FILE* bakCheck = nullptr;
    fopen_s(&bakCheck, bak.c_str(), "rb");
    if (bakCheck) {
        fclose(bakCheck);
        printf("backup %s already exists - not overwriting it (it holds the true original)\n", bak.c_str());
    } else {
        FILE* bf = nullptr;
        fopen_s(&bf, bak.c_str(), "wb");
        if (!bf) { fprintf(stderr, "could not create backup %s - refusing to patch\n", bak.c_str()); return 7; }
        fwrite(data.data(), 1, data.size(), bf);
        fclose(bf);
        printf("backup written: %s\n", bak.c_str());
    }

    int32_t newValue = *patchTo;
    memcpy(&data[target + 1], &newValue, 4);

    FILE* wf = nullptr;
    fopen_s(&wf, path.c_str(), "wb");
    if (!wf) { fprintf(stderr, "could not write %s\n", path.c_str()); return 8; }
    fwrite(data.data(), 1, data.size(), wf);
    fclose(wf);

    printf("patched 0x%08X : %d -> %d\n", target, oldValue, newValue);
    return 0;
}
