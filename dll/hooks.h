#pragma once
#ifndef HOOKS_H
#define HOOKS_H

#include "globals.h"
#include <string>

bool        HookInit();
void        HookCleanup();
std::string CmdHook(uint64_t addr, const std::string& name);
std::string CmdUnhook(uint64_t addr);
std::string CmdHookList();
std::string CmdHookLog(uint64_t addr, int count);

#endif // HOOKS_H
