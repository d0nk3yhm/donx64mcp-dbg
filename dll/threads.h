#pragma once
#ifndef THREADS_H
#define THREADS_H

#include "globals.h"
#include <string>

std::string CmdThreads();
std::string CmdThreadCtx(DWORD tid);
std::string CmdThreadSet(DWORD tid, const std::string& reg, uint64_t value);
std::string CmdThreadSuspend(DWORD tid);
std::string CmdThreadResume(DWORD tid);
std::string CmdCallStack(DWORD tid);

#endif // THREADS_H
