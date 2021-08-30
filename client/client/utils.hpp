#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include "nt.hpp"

namespace utils
{
	bool ReadFileToMemory(const std::string& file_path, std::vector<uint8_t>* out_buffer);
	uint32_t GetProcessIdByName(const std::string& process_name);
	std::string GetProcessNameById(uint32_t pid);
	bool ProcessExists(uint32_t pid);
	bool ProcessExists(const std::string& process_name);
	uint64_t GetKernelModuleAddress(const std::string& module_name);
	DWORD GetThreadIdFromProcessId(uint32_t process_id);
}