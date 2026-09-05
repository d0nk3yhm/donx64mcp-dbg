#pragma once
#ifndef HOOKS_H
#define HOOKS_H

#include "globals.h"
#include <string>

bool        HookInit();
void        HookCleanup();
std::string CmdHook(uint64_t addr, const std::string& name);
std::string CmdHookScanCaller(uint64_t addr, int scan_window, const std::string& pattern_csv,
                               const std::string& replacement_csv, const std::string& name);
std::string CmdHookScanOutput(uint64_t addr, int buf_arg_index, int len_arg_index, bool len_is_out_pointer,
                               const std::string& pattern_csv, int patch_offset,
                               const std::string& replacement_csv, const std::string& name);
std::string CmdUnhook(uint64_t addr);
std::string CmdHookList();
std::string CmdHookLog(uint64_t addr, int count);

#endif // HOOKS_H
