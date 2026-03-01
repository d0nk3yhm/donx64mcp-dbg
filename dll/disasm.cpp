#include "disasm.h"
#include "memory_ops.h"
#include "response.h"

// Zydis amalgamated v4.1.0 (Zycore bundled inside)
#include "Zydis.h"

#include <vector>
#include <cstdio>

// ── Zydis state ─────────────────────────────────────────────────────────

static ZydisDecoder    g_decoder;
static ZydisFormatter  g_formatter;
static bool            g_disasm_ready = false;

bool DisasmInit() {
    if (ZydisDecoderInit(&g_decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64) != ZYAN_STATUS_SUCCESS)
        return false;
    if (ZydisFormatterInit(&g_formatter, ZYDIS_FORMATTER_STYLE_INTEL) != ZYAN_STATUS_SUCCESS)
        return false;
    g_disasm_ready = true;
    return true;
}

// ── Disassemble N instructions ──────────────────────────────────────────

std::string CmdDisasm(uint64_t addr, int count) {
    if (!g_disasm_ready)
        return ErrorResponse("disassembler not initialized");
    if (count <= 0) count = 10;
    if (count > MCP_MAX_DISASM) count = MCP_MAX_DISASM;

    // Read a chunk of memory (15 bytes per instruction max for x64)
    size_t read_size = (size_t)count * 15;
    if (read_size > 8192) read_size = 8192;
    std::vector<uint8_t> buf(read_size);

    if (!MemReadSafe((void*)addr, buf.data(), read_size))
        return ErrorResponse("failed to read memory at address");

    std::vector<std::string> instructions;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    size_t offset = 0;

    for (int i = 0; i < count && offset < read_size; i++) {
        if (ZydisDecoderDecodeFull(&g_decoder, buf.data() + offset, read_size - offset,
                                    &instruction, operands) != ZYAN_STATUS_SUCCESS) {
            // Failed to decode - emit as db
            char db_buf[64];
            snprintf(db_buf, sizeof(db_buf), "db 0x%02X", buf[offset]);
            uint64_t inst_addr = addr + offset;

            instructions.push_back(
                Response()
                    .addHex("address", inst_addr)
                    .addHex("rva", inst_addr - g_base_address)
                    .add("bytes", bytes_to_hex(buf.data() + offset, 1))
                    .add("mnemonic", std::string(db_buf))
                    .add("length", (int64_t)1)
                    .build()
            );
            offset += 1;
            continue;
        }

        char formatted[256];
        uint64_t inst_addr = addr + offset;
        ZydisFormatterFormatInstruction(&g_formatter, &instruction, operands,
            instruction.operand_count_visible, formatted, sizeof(formatted), inst_addr, ZYAN_NULL);

        // Split mnemonic and operands
        std::string full(formatted);
        std::string mnemonic, ops;
        size_t space = full.find(' ');
        if (space != std::string::npos) {
            mnemonic = full.substr(0, space);
            ops = full.substr(space + 1);
        } else {
            mnemonic = full;
        }

        instructions.push_back(
            Response()
                .addHex("address", inst_addr)
                .addHex("rva", inst_addr - g_base_address)
                .add("bytes", bytes_to_hex(buf.data() + offset, instruction.length))
                .add("mnemonic", mnemonic)
                .add("operands", ops)
                .add("text", full)
                .add("length", (int64_t)instruction.length)
                .build()
        );

        offset += instruction.length;
    }

    return Response()
        .add("status", "ok")
        .addHex("base_address", addr)
        .add("count", (int64_t)instructions.size())
        .addRawArray("instructions", instructions)
        .build();
}

// ── Disassemble until RET ───────────────────────────────────────────────

std::string CmdDisasmFunc(uint64_t addr) {
    if (!g_disasm_ready)
        return ErrorResponse("disassembler not initialized");

    // Read up to 4KB for a function
    size_t read_size = 4096;
    std::vector<uint8_t> buf(read_size);

    if (!MemReadSafe((void*)addr, buf.data(), read_size))
        return ErrorResponse("failed to read memory at address");

    std::vector<std::string> instructions;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    size_t offset = 0;
    int max_insn = 500;

    // Skip leading INT3 padding bytes (compiler alignment between functions)
    uint64_t func_start = addr;
    while (offset < read_size && buf[offset] == 0xCC) {
        offset++;
        func_start++;
    }

    for (int i = 0; i < max_insn && offset < read_size; i++) {
        if (ZydisDecoderDecodeFull(&g_decoder, buf.data() + offset, read_size - offset,
                                    &instruction, operands) != ZYAN_STATUS_SUCCESS) {
            break;
        }

        char formatted[256];
        uint64_t inst_addr = addr + offset;
        ZydisFormatterFormatInstruction(&g_formatter, &instruction, operands,
            instruction.operand_count_visible, formatted, sizeof(formatted), inst_addr, ZYAN_NULL);

        std::string full(formatted);
        std::string mnemonic, ops;
        size_t space = full.find(' ');
        if (space != std::string::npos) {
            mnemonic = full.substr(0, space);
            ops = full.substr(space + 1);
        } else {
            mnemonic = full;
        }

        instructions.push_back(
            Response()
                .addHex("address", inst_addr)
                .add("bytes", bytes_to_hex(buf.data() + offset, instruction.length))
                .add("text", full)
                .add("length", (int64_t)instruction.length)
                .build()
        );

        offset += instruction.length;

        // Stop on RET
        if (instruction.mnemonic == ZYDIS_MNEMONIC_RET)
            break;
        // Stop on INT3 only when it's inter-function padding (consecutive CC bytes after code)
        // A single INT3 after a RET or at the end is padding; INT3 inside code is a breakpoint
        if (instruction.mnemonic == ZYDIS_MNEMONIC_INT3) {
            // Peek ahead: if next byte is also CC it's padding, stop here
            if (offset < read_size && buf[offset] == 0xCC)
                break;
            // Otherwise it may be a deliberate int3 inside the function, continue
        }
    }

    return Response()
        .add("status", "ok")
        .addHex("queried_address", addr)
        .addHex("function_start", func_start)
        .add("count", (int64_t)instructions.size())
        .add("total_bytes", (int64_t)offset)
        .addRawArray("instructions", instructions)
        .build();
}
