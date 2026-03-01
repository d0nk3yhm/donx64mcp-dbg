#pragma once
#ifndef HEAP_H
#define HEAP_H

#include "globals.h"
#include <string>

std::string CmdHeaps();
std::string CmdHeapWalk(uint64_t heap_id, int max_entries);

#endif // HEAP_H
