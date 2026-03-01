#pragma once
#ifndef COMMANDS_H
#define COMMANDS_H

#include <string>

// Master command dispatcher - takes raw command string, returns JSON response
std::string DispatchCommand(const std::string& command);

#endif // COMMANDS_H
