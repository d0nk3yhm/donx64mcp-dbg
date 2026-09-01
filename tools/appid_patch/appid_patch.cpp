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
    uint32_t fileOffset;      // offset of the ldc opcode byte
    int32_t  value;           // the literal int32
    uint8_t  valueLen;        // 4 (ldc.i4) or 1 (ldc.i4.s) - how many bytes the literal occupies
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

static bool IsCallLike(uint8_t op) { return op == 0x73 || op == 0x28 || op == 0x6F; }

// A candidate is: ldc.i4 <int32> (opcode 0x20, 5 bytes) OR ldc.i4.s <sbyte>
// (opcode 0x1F, 2 bytes) - the short form only exists for values -128..127, which
// covers real Steam's oldest, lowest AppIDs (Half-Life is 10) - immediately
// followed by newobj/call/callvirt (0x73/0x28/0x6F), each taking a 4-byte
// metadata token. That instruction pair is exactly what `new AppId_t(N)` or
// `SteamAPI.RestartAppIfNecessary(N)` compiles to, and it survives essentially
// unchanged through Mono/IL2CPP builds since obfuscation that targets Unity
// games overwhelmingly leaves IL constants alone.
//
// filterValue, when set, requires an EXACT match on the literal - this is the
// primary workflow (you already know the real AppID from steam_appid.txt or
// the store page, so search for THAT specific number, the same way a human
// reversing this by hand would - not a blind dump of every ldc.i4 in a range).
static std::vector<Candidate> Scan(const std::vector<uint8_t>& data, uint32_t start,
                                    uint32_t end, int64_t minVal, int64_t maxVal,
                                    std::optional<int32_t> filterValue) {
    std::vector<Candidate> out;
    if (end > data.size()) end = (uint32_t)data.size();
    for (uint32_t i = start; i < end; i++) {
        int32_t val; uint8_t valLen; uint32_t followAt;
        if (data[i] == 0x20 && i + 5 <= end) {                 // ldc.i4 <int32>
            memcpy(&val, &data[i + 1], 4);
            valLen = 4; followAt = i + 5;
        } else if (data[i] == 0x1F && i + 2 <= end) {          // ldc.i4.s <sbyte>
            val = (int8_t)data[i + 1];
            valLen = 1; followAt = i + 2;
        } else {
            continue;
        }
        if (followAt + 5 > end) continue;
        if (filterValue) { if (val != *filterValue) continue; }
        else { if (val < minVal || val > maxVal) continue; }
        uint8_t follow = data[followAt];
        if (!IsCallLike(follow)) continue;
        uint32_t token;
        memcpy(&token, &data[followAt + 1], 4);
        Candidate c{ i, val, valLen, follow, token, TokenTableName(token) };
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
        "The workflow that actually works: you already know the REAL AppID (it's in\n"
        "steam_appid.txt, the store page URL, or the game's SteamDB entry) - search for\n"
        "THAT number specifically, the same way you'd grep for it by hand. A blind dump\n"
        "of every small integer constant in the file is not a usable answer; searching\n"
        "for a number you already know almost always is.\n\n"
        "Usage:\n"
        "  %s <dll> --find OLDVALUE                       find occurrences of a KNOWN AppID (primary use)\n"
        "  %s <dll> --find OLDVALUE --patch NEW           find, and patch if there's exactly one hit\n"
        "  %s <dll> --find OLDVALUE --patch NEW --at 0xOFF  patch one specific hit (when --find has several)\n"
        "  %s <dll> --min N --max N                       don't know the real AppID? list everything\n"
        "                                                   plausible in a range instead (usually noisy)\n\n"
        "Always writes <dll>.bak (once; refuses to overwrite an existing one) before patching.\n",
        argv0, argv0, argv0, argv0);
}

int main(int argc, char** argv) {
    if (argc < 2) { Usage(argv[0]); return 1; }
    std::string path = argv[1];
    int64_t minVal = 1, maxVal = 5000000;   // only used when --find is absent
    std::optional<int32_t> findValue;
    std::optional<int32_t> patchTo;
    std::optional<uint32_t> atOffset;
    bool rangeGiven = false;

    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&](const char* name) -> std::string {
            if (i + 1 >= argc) { fprintf(stderr, "%s needs a value\n", name); exit(2); }
            return argv[++i];
        };
        if (a == "--find") findValue = (int32_t)_atoi64(next("--find").c_str());
        else if (a == "--min") { minVal = _atoi64(next("--min").c_str()); rangeGiven = true; }
        else if (a == "--max") { maxVal = _atoi64(next("--max").c_str()); rangeGiven = true; }
        else if (a == "--patch") patchTo = (int32_t)_atoi64(next("--patch").c_str());
        else if (a == "--at") atOffset = (uint32_t)strtoul(next("--at").c_str(), nullptr, 0);
        else { fprintf(stderr, "unknown argument: %s\n", a.c_str()); Usage(argv[0]); return 2; }
    }
    if (!findValue && !rangeGiven) {
        fprintf(stderr, "Need either --find OLDVALUE (you know the real AppID - use this) "
                        "or --min/--max (a range dump, for when you don't).\n\n");
        Usage(argv[0]);
        return 1;
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
    auto candidates = Scan(data, scanStart, scanEnd, minVal, maxVal, findValue);

    if (findValue) {
        printf("\n%zu occurrence(s) of %d immediately followed by newobj/call/callvirt:\n",
               candidates.size(), *findValue);
    } else {
        printf("\n%zu candidate literal(s) in [%lld, %lld] immediately followed by "
               "newobj/call/callvirt (this is a discovery dump, not a targeted search - "
               "most of these are unrelated constants):\n",
               candidates.size(), (long long)minVal, (long long)maxVal);
    }
    for (auto& c : candidates) {
        printf("  file offset 0x%08X : %-9s %-10d  %s  token 0x%08X (%s)\n",
               c.fileOffset, c.valueLen == 1 ? "ldc.i4.s" : "ldc.i4", c.value,
               OpName(c.followOp), c.token, c.tokenTable);
    }
    if (findValue && candidates.empty()) {
        printf("\nNot found in this exact ldc.i4/ldc.i4.s + newobj/call/callvirt form. Either this\n"
               "build doesn't embed the AppID as a plain IL constant here, or it's shaped\n"
               "differently (split across two half-word loads, XOR-masked, etc.) - that would\n"
               "need a fresh look at the IL around wherever RestartAppIfNecessary is called.\n");
    }

    if (!patchTo) {
        if (!candidates.empty())
            printf("\nTo patch, add --patch NEW%s\n",
                   candidates.size() == 1 ? " (there's exactly one hit, no --at needed)"
                                          : " --at 0xOFFSET (pick one of the offsets above)");
        return 0;
    }

    // ---- patch mode ----
    uint32_t target;
    const Candidate* targetC = nullptr;
    if (atOffset) {
        target = *atOffset;
        for (auto& c : candidates) if (c.fileOffset == target) { targetC = &c; break; }
        if (!targetC) {
            fprintf(stderr, "0x%X is not one of the occurrences listed above - refusing to patch a "
                            "location this tool didn't itself identify as ldc.i4/ldc.i4.s + "
                            "newobj/call/callvirt.\n", target);
            return 5;
        }
    } else {
        if (candidates.size() != 1) {
            fprintf(stderr, "%zu occurrences found; --patch needs --at 0xOFFSET to say which one "
                            "(auto-picking with more than one match would be a guess).\n",
                    candidates.size());
            return 6;
        }
        targetC = &candidates[0];
        target = targetC->fileOffset;
    }

    int32_t newValue = *patchTo;
    if (targetC->valueLen == 1 && (newValue < -128 || newValue > 127)) {
        fprintf(stderr, "0x%X is a short-form ldc.i4.s (1-byte operand) and %d does not fit in a "
                        "signed byte. Widening it to the long form would change the instruction's\n"
                        "length and shift every offset after it (branch targets, exception handler\n"
                        "ranges, method body sizes) - not a safe in-place byte patch. Refusing.\n",
                target, newValue);
        return 9;
    }

    int32_t oldValue = targetC->value;

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

    if (targetC->valueLen == 1) {
        int8_t nv = (int8_t)newValue;
        data[target + 1] = (uint8_t)nv;
    } else {
        memcpy(&data[target + 1], &newValue, 4);
    }

    FILE* wf = nullptr;
    fopen_s(&wf, path.c_str(), "wb");
    if (!wf) { fprintf(stderr, "could not write %s\n", path.c_str()); return 8; }
    fwrite(data.data(), 1, data.size(), wf);
    fclose(wf);

    printf("patched 0x%08X : %d -> %d\n", target, oldValue, newValue);
    return 0;
}
