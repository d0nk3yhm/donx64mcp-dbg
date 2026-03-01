#pragma once
#ifndef DISASM_H
#define DISASM_H

#include "globals.h"
#include <string>

bool        DisasmInit();
std::string CmdDisasm(uint64_t addr, int count);
std::string CmdDisasmFunc(uint64_t addr);

#endif // DISASM_H
