#pragma once
#ifndef BREAKPOINTS_H
#define BREAKPOINTS_H

#include "globals.h"
#include <string>

struct Breakpoint {
    uint64_t address;
    uint8_t  original_byte;
    bool     enabled;
    bool     active;       // Is it set in memory?
    bool     one_shot;
    int      hit_count;
    CONTEXT  last_context;
    DWORD    last_thread_id;
    uint64_t last_hit_tick;
    bool     hit_pending;  // New hit waiting to be read
};

void        BreakpointInit();
void        BreakpointCleanup();

std::string CmdBpSet(uint64_t addr);
std::string CmdBpDel(uint64_t addr);
std::string CmdBpList();
std::string CmdBpCtx(uint64_t addr);
std::string CmdBpWait(uint64_t addr, DWORD timeout_ms);
std::string CmdBpEnable(uint64_t addr);
std::string CmdBpDisable(uint64_t addr);

#endif // BREAKPOINTS_H
