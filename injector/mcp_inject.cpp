#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <vector>

#pragma comment(lib, "Shlwapi.lib")

// ── Find process by name ────────────────────────────────────────────────

static DWORD FindProcessByName(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    DWORD pid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

// ── Check if a module is loaded in a process ────────────────────────────

static bool IsModuleLoaded(DWORD pid, const char* dll_name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32 me;
    me.dwSize = sizeof(me);

    bool found = false;
    if (Module32First(snap, &me)) {
        do {
            if (_stricmp(me.szModule, dll_name) == 0) {
                found = true;
                break;
            }
        } while (Module32Next(snap, &me));
    }

    CloseHandle(snap);
    return found;
}

// ═════════════════════════════════════════════════════════════════════════
// LoadLibrary Injection (original method)
// ═════════════════════════════════════════════════════════════════════════

static bool InjectDLL(DWORD pid, const char* dll_path) {
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid
    );

    if (!hProcess) {
        printf("[!] Failed to open process %lu (error %lu)\n", pid, GetLastError());
        printf("    Try running as Administrator\n");
        return false;
    }

    char full_path[MAX_PATH];
    if (!GetFullPathNameA(dll_path, MAX_PATH, full_path, NULL)) {
        printf("[!] Invalid DLL path: %s\n", dll_path);
        CloseHandle(hProcess);
        return false;
    }

    DWORD attrs = GetFileAttributesA(full_path);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        printf("[!] DLL not found: %s\n", full_path);
        CloseHandle(hProcess);
        return false;
    }

    size_t path_size = strlen(full_path) + 1;

    void* remote_mem = VirtualAllocEx(hProcess, NULL, path_size,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_mem) {
        printf("[!] VirtualAllocEx failed (error %lu)\n", GetLastError());
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, remote_mem, full_path, path_size, NULL)) {
        printf("[!] WriteProcessMemory failed (error %lu)\n", GetLastError());
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    FARPROC pLoadLib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                         (LPTHREAD_START_ROUTINE)pLoadLib,
                                         remote_mem, 0, NULL);
    if (!hThread) {
        printf("[!] CreateRemoteThread failed (error %lu)\n", GetLastError());
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, 5000);

    DWORD exit_code = 0;
    GetExitCodeThread(hThread, &exit_code);

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    if (exit_code == 0) {
        printf("[!] LoadLibraryA returned NULL - injection may have failed\n");
        return false;
    }

    return true;
}

// ═════════════════════════════════════════════════════════════════════════
// Manual Map Injection
// ═════════════════════════════════════════════════════════════════════════

// Read entire file into a buffer
static bool ReadFileToBuffer(const char* path, std::vector<BYTE>& buffer) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Cannot open file: %s (error %lu)\n", path, GetLastError());
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        printf("[!] Invalid file size: %s\n", path);
        CloseHandle(hFile);
        return false;
    }

    buffer.resize(fileSize);
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        printf("[!] Failed to read file: %s (error %lu)\n", path, GetLastError());
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);
    return true;
}

// Convert PE section characteristics to memory protection flags
static DWORD SectionProtect(DWORD characteristics) {
    bool exec  = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    bool read  = (characteristics & IMAGE_SCN_MEM_READ)    != 0;
    bool write = (characteristics & IMAGE_SCN_MEM_WRITE)   != 0;

    if (exec && write && read) return PAGE_EXECUTE_READWRITE;
    if (exec && read)          return PAGE_EXECUTE_READ;
    if (exec && write)         return PAGE_EXECUTE_WRITECOPY;
    if (exec)                  return PAGE_EXECUTE;
    if (write && read)         return PAGE_READWRITE;
    if (read)                  return PAGE_READONLY;
    if (write)                 return PAGE_WRITECOPY;
    return PAGE_NOACCESS;
}

// Process base relocations
static bool ProcessRelocations(BYTE* localImage, UINT_PTR remoteBase, UINT_PTR preferredBase) {
    INT_PTR delta = (INT_PTR)(remoteBase - preferredBase);
    if (delta == 0) return true; // No relocation needed

    auto* dosHeader = (IMAGE_DOS_HEADER*)localImage;
    auto* ntHeaders = (IMAGE_NT_HEADERS64*)(localImage + dosHeader->e_lfanew);
    auto& relocDir  = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (relocDir.VirtualAddress == 0 || relocDir.Size == 0) {
        printf("[!] No relocation table and image needs rebasing!\n");
        return false;
    }

    BYTE* relocBase = localImage + relocDir.VirtualAddress;
    DWORD relocSize = relocDir.Size;
    DWORD offset = 0;

    while (offset < relocSize) {
        auto* block = (IMAGE_BASE_RELOCATION*)(relocBase + offset);
        if (block->SizeOfBlock == 0) break;

        DWORD entryCount = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entries = (WORD*)(block + 1);

        for (DWORD i = 0; i < entryCount; i++) {
            WORD type   = entries[i] >> 12;
            WORD rvaOff = entries[i] & 0x0FFF;

            if (type == IMAGE_REL_BASED_DIR64) {
                // 64-bit relocation
                UINT_PTR* patchAddr = (UINT_PTR*)(localImage + block->VirtualAddress + rvaOff);
                *patchAddr += delta;
            }
            else if (type == IMAGE_REL_BASED_HIGHLOW) {
                // 32-bit relocation (rare in x64 but handle it)
                DWORD* patchAddr = (DWORD*)(localImage + block->VirtualAddress + rvaOff);
                *patchAddr += (DWORD)delta;
            }
            else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                // Padding, skip
            }
            else {
                printf("[!] Unknown relocation type %d at block RVA 0x%X\n",
                       type, block->VirtualAddress);
            }
        }

        offset += block->SizeOfBlock;
    }

    return true;
}

// Known DLLs that are guaranteed same base address in all processes (per-boot ASLR)
static bool IsKnownDll(const char* name) {
    static const char* knownDlls[] = {
        "kernel32.dll", "kernelbase.dll", "ntdll.dll", "user32.dll",
        "gdi32.dll", "advapi32.dll", "shell32.dll", "ole32.dll",
        "oleaut32.dll", "msvcrt.dll", "ws2_32.dll", "sechost.dll",
        "rpcrt4.dll", "combase.dll", "ucrtbase.dll", "bcryptprimitives.dll",
        "imm32.dll", "win32u.dll", "gdi32full.dll", "msvcp_win.dll",
        "clbcatq.dll", "setupapi.dll", "cfgmgr32.dll", "comdlg32.dll",
        "shcore.dll", "shlwapi.dll", "wldap32.dll", "crypt32.dll",
        "msasn1.dll", "imagehlp.dll", "normaliz.dll", "nsi.dll",
        "psapi.dll", "powrprof.dll", "profapi.dll", "wintrust.dll",
        NULL
    };
    for (int i = 0; knownDlls[i]; i++) {
        if (_stricmp(name, knownDlls[i]) == 0) return true;
    }
    return false;
}

// Pre-load non-system DLLs into the target process via LoadLibrary
// so their addresses are valid when we resolve imports
static bool PreloadDependencies(HANDLE hProcess, BYTE* localImage) {
    auto* dosHeader = (IMAGE_DOS_HEADER*)localImage;
    auto* ntHeaders = (IMAGE_NT_HEADERS64*)(localImage + dosHeader->e_lfanew);
    auto& importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (importDir.VirtualAddress == 0 || importDir.Size == 0) return true;

    auto* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(localImage + importDir.VirtualAddress);
    FARPROC pLoadLib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    while (importDesc->Name) {
        const char* dllName = (const char*)(localImage + importDesc->Name);

        if (!IsKnownDll(dllName)) {
            // Check if it's already loaded in the target
            // We need to load it there so addresses match
            printf("[*] Pre-loading dependency: %s\n", dllName);

            size_t nameLen = strlen(dllName) + 1;
            void* remoteName = VirtualAllocEx(hProcess, NULL, nameLen,
                                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!remoteName) {
                printf("[!] VirtualAllocEx for DLL name failed\n");
                return false;
            }

            WriteProcessMemory(hProcess, remoteName, dllName, nameLen, NULL);

            HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                                 (LPTHREAD_START_ROUTINE)pLoadLib,
                                                 remoteName, 0, NULL);
            if (hThread) {
                WaitForSingleObject(hThread, 5000);
                DWORD exitCode = 0;
                GetExitCodeThread(hThread, &exitCode);
                CloseHandle(hThread);

                if (exitCode == 0) {
                    printf("[!] Failed to load %s in target process\n", dllName);
                    VirtualFreeEx(hProcess, remoteName, 0, MEM_RELEASE);
                    return false;
                }
            } else {
                printf("[!] CreateRemoteThread for LoadLibrary failed\n");
                VirtualFreeEx(hProcess, remoteName, 0, MEM_RELEASE);
                return false;
            }

            VirtualFreeEx(hProcess, remoteName, 0, MEM_RELEASE);

            // Now load it in our process too so GetProcAddress works
            LoadLibraryA(dllName);
        }

        importDesc++;
    }

    return true;
}

// Resolve imports — walk IAT and fill in function addresses
// hProcess is needed to read module base addresses from target for non-known DLLs
static bool ResolveImports(BYTE* localImage, HANDLE hProcess) {
    auto* dosHeader = (IMAGE_DOS_HEADER*)localImage;
    auto* ntHeaders = (IMAGE_NT_HEADERS64*)(localImage + dosHeader->e_lfanew);
    auto& importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (importDir.VirtualAddress == 0 || importDir.Size == 0) {
        return true; // No imports — unlikely for a real DLL but valid
    }

    auto* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(localImage + importDir.VirtualAddress);

    while (importDesc->Name) {
        const char* dllName = (const char*)(localImage + importDesc->Name);

        // Load the dependency in OUR process to resolve addresses
        HMODULE hMod = GetModuleHandleA(dllName);
        if (!hMod) {
            hMod = LoadLibraryA(dllName);
            if (!hMod) {
                printf("[!] Cannot resolve import DLL: %s (error %lu)\n", dllName, GetLastError());
                return false;
            }
        }

        // For non-known DLLs, we need to find where it's loaded in the target
        // and compute the offset to adjust addresses
        UINT_PTR localBase = (UINT_PTR)hMod;
        UINT_PTR remoteModBase = localBase; // Same for known DLLs

        if (!IsKnownDll(dllName)) {
            // Find the DLL's base in the target process using toolhelp
            DWORD pid = GetProcessId(hProcess);
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if (snap != INVALID_HANDLE_VALUE) {
                MODULEENTRY32 me;
                me.dwSize = sizeof(me);
                if (Module32First(snap, &me)) {
                    do {
                        if (_stricmp(me.szModule, dllName) == 0) {
                            remoteModBase = (UINT_PTR)me.modBaseAddr;
                            break;
                        }
                    } while (Module32Next(snap, &me));
                }
                CloseHandle(snap);
            }
        }

        INT_PTR modDelta = (INT_PTR)(remoteModBase - localBase);

        // Walk the thunk arrays
        auto* origThunk = (IMAGE_THUNK_DATA64*)(localImage +
            (importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk));
        auto* iatThunk  = (IMAGE_THUNK_DATA64*)(localImage + importDesc->FirstThunk);

        while (origThunk->u1.AddressOfData) {
            FARPROC funcAddr = NULL;

            if (IMAGE_SNAP_BY_ORDINAL64(origThunk->u1.Ordinal)) {
                // Import by ordinal
                WORD ordinal = (WORD)IMAGE_ORDINAL64(origThunk->u1.Ordinal);
                funcAddr = GetProcAddress(hMod, MAKEINTRESOURCEA(ordinal));
                if (!funcAddr) {
                    printf("[!] Cannot resolve ordinal %d from %s\n", ordinal, dllName);
                    return false;
                }
            } else {
                // Import by name
                auto* importByName = (IMAGE_IMPORT_BY_NAME*)(localImage + origThunk->u1.AddressOfData);
                funcAddr = GetProcAddress(hMod, importByName->Name);
                if (!funcAddr) {
                    printf("[!] Cannot resolve %s!%s\n", dllName, importByName->Name);
                    return false;
                }
            }

            // Apply delta for non-known DLLs
            iatThunk->u1.Function = (ULONGLONG)((UINT_PTR)funcAddr + modDelta);

            origThunk++;
            iatThunk++;
        }

        importDesc++;
    }

    return true;
}

// Find an exported function RVA from a locally-mapped PE image
static DWORD FindExportRVA(BYTE* localImage, const char* funcName) {
    auto* dosHeader = (IMAGE_DOS_HEADER*)localImage;
    auto* ntHeaders = (IMAGE_NT_HEADERS64*)(localImage + dosHeader->e_lfanew);
    auto& exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) return 0;

    auto* exports = (IMAGE_EXPORT_DIRECTORY*)(localImage + exportDir.VirtualAddress);
    DWORD* names    = (DWORD*)(localImage + exports->AddressOfNames);
    WORD*  ordinals = (WORD*)(localImage + exports->AddressOfNameOrdinals);
    DWORD* funcs    = (DWORD*)(localImage + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char* name = (const char*)(localImage + names[i]);
        if (strcmp(name, funcName) == 0) {
            return funcs[ordinals[i]];
        }
    }

    return 0;
}

// Execute ManualMapInit in the remote process
// ManualMapInit has LPTHREAD_START_ROUTINE signature: DWORD WINAPI Func(LPVOID)
// So we can use CreateRemoteThread directly — no shellcode needed!
static bool ExecuteRemoteInit(HANDLE hProcess, UINT_PTR remoteBase, DWORD initRVA) {
    UINT_PTR initAddr = remoteBase + initRVA;

    printf("[*] ManualMapInit at remote address: 0x%llX\n", (unsigned long long)initAddr);

    // CreateRemoteThread calls our exported function directly.
    // ManualMapInit(LPVOID pImageBase) — we pass the image base as the parameter.
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                         (LPTHREAD_START_ROUTINE)initAddr,
                                         (LPVOID)remoteBase, 0, NULL);
    if (!hThread) {
        printf("[!] CreateRemoteThread for ManualMapInit failed (error %lu)\n", GetLastError());
        return false;
    }

    // Wait for init to finish
    DWORD waitResult = WaitForSingleObject(hThread, 10000);
    if (waitResult == WAIT_TIMEOUT) {
        printf("[!] ManualMapInit did not return within 10 seconds\n");
        CloseHandle(hThread);
        return false;
    }

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);

    if (exitCode != 1) {
        printf("[!] ManualMapInit returned %lu (expected 1)\n", exitCode);
        return false;
    }

    return true;
}

// Main manual map function
static bool ManualMapInject(DWORD pid, const char* dll_path) {
    // ── Step 1: Read PE from disk ───────────────────────────────────
    char full_path[MAX_PATH];
    if (!GetFullPathNameA(dll_path, MAX_PATH, full_path, NULL)) {
        printf("[!] Invalid DLL path: %s\n", dll_path);
        return false;
    }

    std::vector<BYTE> fileBuffer;
    if (!ReadFileToBuffer(full_path, fileBuffer)) {
        return false;
    }

    printf("[*] Read %zu bytes from %s\n", fileBuffer.size(), full_path);

    // ── Step 2: Validate PE ─────────────────────────────────────────
    if (fileBuffer.size() < sizeof(IMAGE_DOS_HEADER)) {
        printf("[!] File too small for PE\n");
        return false;
    }

    auto* dosHeader = (IMAGE_DOS_HEADER*)fileBuffer.data();
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Invalid DOS signature\n");
        return false;
    }

    if ((size_t)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > fileBuffer.size()) {
        printf("[!] Invalid PE offset\n");
        return false;
    }

    auto* ntHeaders = (IMAGE_NT_HEADERS64*)(fileBuffer.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Invalid NT signature\n");
        return false;
    }

    if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        printf("[!] Not an x64 PE (machine = 0x%X)\n", ntHeaders->FileHeader.Machine);
        return false;
    }

    if (!(ntHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
        printf("[!] PE is not a DLL\n");
        return false;
    }

    DWORD imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    UINT_PTR preferredBase = ntHeaders->OptionalHeader.ImageBase;
    DWORD sizeOfHeaders = ntHeaders->OptionalHeader.SizeOfHeaders;
    WORD numSections = ntHeaders->FileHeader.NumberOfSections;

    printf("[*] ImageSize: 0x%X, Sections: %d\n", imageSize, numSections);

    // ── Step 3: Open target process ─────────────────────────────────
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid
    );

    if (!hProcess) {
        printf("[!] Failed to open process %lu (error %lu)\n", pid, GetLastError());
        printf("    Try running as Administrator\n");
        return false;
    }

    // ── Step 4: Allocate memory in target ───────────────────────────
    // Try preferred base first, then any address
    void* remoteBase = VirtualAllocEx(hProcess, (void*)preferredBase, imageSize,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBase) {
        // Preferred base unavailable, allocate anywhere
        remoteBase = VirtualAllocEx(hProcess, NULL, imageSize,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }

    if (!remoteBase) {
        printf("[!] VirtualAllocEx failed for image (error %lu)\n", GetLastError());
        CloseHandle(hProcess);
        return false;
    }

    printf("[*] Remote allocation at: 0x%p (preferred: 0x%llX)\n",
           remoteBase, (unsigned long long)preferredBase);

    // ── Step 5: Prepare local mapped image ──────────────────────────
    // Create a zeroed buffer of SizeOfImage and map sections into it
    std::vector<BYTE> mappedImage(imageSize, 0);

    // Copy headers
    memcpy(mappedImage.data(), fileBuffer.data(), sizeOfHeaders);

    // Copy sections
    auto* sections = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < numSections; i++) {
        if (sections[i].SizeOfRawData == 0) continue;

        if (sections[i].PointerToRawData + sections[i].SizeOfRawData > fileBuffer.size()) {
            printf("[!] Section %d raw data exceeds file size\n", i);
            VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        DWORD copySize = min(sections[i].SizeOfRawData, sections[i].Misc.VirtualSize);
        memcpy(mappedImage.data() + sections[i].VirtualAddress,
               fileBuffer.data() + sections[i].PointerToRawData,
               copySize);

        printf("    Section %-8.8s: RVA 0x%06X, Size 0x%06X\n",
               (char*)sections[i].Name, sections[i].VirtualAddress, copySize);
    }

    // ── Step 6: Process relocations ─────────────────────────────────
    if (!ProcessRelocations(mappedImage.data(), (UINT_PTR)remoteBase, preferredBase)) {
        printf("[!] Relocation processing failed\n");
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    if ((UINT_PTR)remoteBase != preferredBase) {
        printf("[*] Relocations applied (delta: 0x%llX)\n",
               (unsigned long long)((UINT_PTR)remoteBase - preferredBase));
    }

    // ── Step 6b: Pre-load non-system dependencies in target ────────
    if (!PreloadDependencies(hProcess, mappedImage.data())) {
        printf("[!] Dependency pre-loading failed\n");
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // ── Step 7: Resolve imports ─────────────────────────────────────
    if (!ResolveImports(mappedImage.data(), hProcess)) {
        printf("[!] Import resolution failed\n");
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    printf("[*] Imports resolved\n");

    // ── Step 8: Write mapped image to remote process ────────────────
    if (!WriteProcessMemory(hProcess, remoteBase, mappedImage.data(), imageSize, NULL)) {
        printf("[!] WriteProcessMemory for image failed (error %lu)\n", GetLastError());
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    printf("[*] Image written to remote process\n");

    // ── Step 9: Set section protections ─────────────────────────────
    // Headers: readonly
    DWORD oldProt;
    VirtualProtectEx(hProcess, remoteBase, sizeOfHeaders, PAGE_READONLY, &oldProt);

    for (WORD i = 0; i < numSections; i++) {
        if (sections[i].Misc.VirtualSize == 0) continue;

        DWORD prot = SectionProtect(sections[i].Characteristics);
        void* sectionAddr = (BYTE*)remoteBase + sections[i].VirtualAddress;
        SIZE_T sectionSize = sections[i].Misc.VirtualSize;

        VirtualProtectEx(hProcess, sectionAddr, sectionSize, prot, &oldProt);
    }
    printf("[*] Section protections applied\n");

    // ── Step 10: Call ManualMapInit directly ────────────────────────
    // We use our exported ManualMapInit which has LPTHREAD_START_ROUTINE
    // signature, so CreateRemoteThread can call it directly.
    // ManualMapInit uses only Win32 APIs — no CRT dependency.
    {
        DWORD initRVA = FindExportRVA(mappedImage.data(), "ManualMapInit");
        if (initRVA == 0) {
            printf("[!] ManualMapInit export not found\n");
            CloseHandle(hProcess);
            return false;
        }

        UINT_PTR initAddr = (UINT_PTR)remoteBase + initRVA;
        printf("[*] ManualMapInit at 0x%llX (RVA 0x%X)\n",
               (unsigned long long)initAddr, initRVA);

        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                             (LPTHREAD_START_ROUTINE)initAddr,
                                             (LPVOID)remoteBase, 0, NULL);
        if (!hThread) {
            printf("[!] CreateRemoteThread failed (error %lu)\n", GetLastError());
            CloseHandle(hProcess);
            return false;
        }

        DWORD waitResult = WaitForSingleObject(hThread, 15000);
        if (waitResult == WAIT_TIMEOUT) {
            printf("[!] ManualMapInit timed out\n");
            CloseHandle(hThread);
            CloseHandle(hProcess);
            return false;
        }

        DWORD exitCode = 0;
        GetExitCodeThread(hThread, &exitCode);
        CloseHandle(hThread);

        if (exitCode != 1) {
            printf("[!] ManualMapInit returned %lu (expected 1)\n", exitCode);
            CloseHandle(hProcess);
            return false;
        }

        printf("[+] ManualMapInit returned successfully\n");
    }

    // ── Step 11: Erase PE headers ────────────────────────────────────
    {
        DWORD oldProt2;
        VirtualProtectEx(hProcess, remoteBase, 0x1000, PAGE_READWRITE, &oldProt2);
        std::vector<BYTE> zeros(0x1000, 0);
        WriteProcessMemory(hProcess, remoteBase, zeros.data(), zeros.size(), NULL);
        VirtualProtectEx(hProcess, remoteBase, 0x1000, PAGE_READONLY, &oldProt2);
        printf("[*] PE headers erased in remote process\n");
    }

    printf("[+] Manual map injection complete\n");

    CloseHandle(hProcess);
    return true;
}

// ═════════════════════════════════════════════════════════════════════════
// Usage / Main
// ═════════════════════════════════════════════════════════════════════════

static void PrintUsage(const char* exe) {
    printf("MCP Debugger Injector\n");
    printf("=====================\n\n");
    printf("Usage:\n");
    printf("  %s --pid <PID> --dll <path>                    Inject into running process\n", exe);
    printf("  %s --name <process.exe> --dll <path>           Inject by process name\n", exe);
    printf("  %s --launch <exe> --dll <path> [--args \"...\"]  Launch + inject\n", exe);
    printf("  %s --wait-dll <name.dll> --in <proc> --dll <path> [--timeout <ms>]\n", exe);
    printf("                                                   Wait for DLL load, then inject\n\n");
    printf("Options:\n");
    printf("  --manualmap, --mm    Use manual mapping instead of LoadLibrary (stealthier)\n\n");
    printf("After injection, connect via named pipe: \\\\.\\pipe\\mcp_dbg_<PID>\n");
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        PrintUsage(argv[0]);
        return 1;
    }

    const char* dll_path    = NULL;
    const char* target_pid  = NULL;
    const char* target_name = NULL;
    const char* launch_exe  = NULL;
    const char* launch_args = NULL;
    const char* wait_dll    = NULL;
    const char* wait_proc   = NULL;
    int  timeout_ms = 30000;
    bool manual_map = false;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
            target_pid = argv[++i];
        } else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) {
            target_name = argv[++i];
        } else if (strcmp(argv[i], "--dll") == 0 && i + 1 < argc) {
            dll_path = argv[++i];
        } else if (strcmp(argv[i], "--launch") == 0 && i + 1 < argc) {
            launch_exe = argv[++i];
        } else if (strcmp(argv[i], "--args") == 0 && i + 1 < argc) {
            launch_args = argv[++i];
        } else if (strcmp(argv[i], "--wait-dll") == 0 && i + 1 < argc) {
            wait_dll = argv[++i];
        } else if (strcmp(argv[i], "--in") == 0 && i + 1 < argc) {
            wait_proc = argv[++i];
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            timeout_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--manualmap") == 0 || strcmp(argv[i], "--mm") == 0) {
            manual_map = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
    }

    if (!dll_path) {
        printf("[!] --dll is required\n");
        return 1;
    }

    // Select injection function based on mode
    auto DoInject = [&](DWORD pid) -> bool {
        if (manual_map) {
            printf("[*] Using manual map injection (stealth mode)\n");
            return ManualMapInject(pid, dll_path);
        } else {
            return InjectDLL(pid, dll_path);
        }
    };

    // ── Mode 1: Inject by PID ───────────────────────────────────────
    if (target_pid) {
        DWORD pid = (DWORD)atoi(target_pid);
        printf("[*] Injecting into PID %lu...\n", pid);

        if (DoInject(pid)) {
            printf("[+] Injection successful!\n");
            printf("[+] Pipe: \\\\.\\pipe\\mcp_dbg_%lu\n", pid);
            return 0;
        }
        return 1;
    }

    // ── Mode 1b: Inject by name ─────────────────────────────────────
    if (target_name) {
        printf("[*] Looking for process: %s\n", target_name);
        DWORD pid = FindProcessByName(target_name);
        if (pid == 0) {
            printf("[!] Process not found: %s\n", target_name);
            return 1;
        }
        printf("[*] Found PID %lu, injecting...\n", pid);

        if (DoInject(pid)) {
            printf("[+] Injection successful!\n");
            printf("[+] Pipe: \\\\.\\pipe\\mcp_dbg_%lu\n", pid);
            return 0;
        }
        return 1;
    }

    // ── Mode 2: Launch suspended + inject ───────────────────────────
    if (launch_exe) {
        printf("[*] Launching: %s\n", launch_exe);

        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        memset(&pi, 0, sizeof(pi));

        char cmd_line[4096];
        if (launch_args)
            snprintf(cmd_line, sizeof(cmd_line), "\"%s\" %s", launch_exe, launch_args);
        else
            snprintf(cmd_line, sizeof(cmd_line), "\"%s\"", launch_exe);

        if (!CreateProcessA(NULL, cmd_line, NULL, NULL, FALSE,
                            CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            printf("[!] CreateProcess failed (error %lu)\n", GetLastError());
            return 1;
        }

        printf("[*] Process created (PID %lu), injecting...\n", pi.dwProcessId);

        if (!DoInject(pi.dwProcessId)) {
            printf("[!] Injection failed, terminating process\n");
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return 1;
        }

        printf("[+] Injection successful, resuming process...\n");
        ResumeThread(pi.hThread);

        printf("[+] Pipe: \\\\.\\pipe\\mcp_dbg_%lu\n", pi.dwProcessId);

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 0;
    }

    // ── Mode 3: Wait for DLL load ───────────────────────────────────
    if (wait_dll && wait_proc) {
        printf("[*] Waiting for %s to load %s (timeout: %dms)...\n",
               wait_proc, wait_dll, timeout_ms);

        DWORD start = GetTickCount();
        DWORD pid = 0;

        while ((GetTickCount() - start) < (DWORD)timeout_ms) {
            pid = FindProcessByName(wait_proc);
            if (pid == 0) {
                Sleep(500);
                continue;
            }

            if (IsModuleLoaded(pid, wait_dll)) {
                printf("[*] %s loaded in PID %lu, injecting...\n", wait_dll, pid);

                if (DoInject(pid)) {
                    printf("[+] Injection successful!\n");
                    printf("[+] Pipe: \\\\.\\pipe\\mcp_dbg_%lu\n", pid);
                    return 0;
                }
                return 1;
            }

            Sleep(200);
        }

        printf("[!] Timeout waiting for %s in %s\n", wait_dll, wait_proc);
        return 1;
    }

    PrintUsage(argv[0]);
    return 1;
}
