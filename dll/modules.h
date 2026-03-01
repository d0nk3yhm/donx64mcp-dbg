#pragma once
#ifndef MODULES_H
#define MODULES_H

#include "globals.h"
#include <string>

std::string CmdModules();
std::string CmdExports(const std::string& module_name);
std::string CmdImports(const std::string& module_name);
std::string CmdSections(const std::string& module_name);

#endif // MODULES_H
