#pragma once
#include <Windows.h>
#include <stdint.h>
#include <string>
#include <vector>
#include "utils.hpp"
#include "driver.hpp"
#include "portable_executable.hpp"
#include "encryption.hpp"

struct Module
{
	std::string name;
	uint64_t image_base;
};

struct MappedModule
{
	std::string module_name;
	uint64_t module_base;
};

using vec_mapped_modules = std::vector<MappedModule>;
using vec_modules = std::vector<Module>;

class Process
{
public:
	Process() : m_pid(0), m_process_name(""), m_is_attached(false) { }
public:
	bool Attach(uint32_t pid);
	bool Attach(std::string process_name);
	bool IsAttached();
	void Deattach();
	bool ReadMemory(uint64_t address, void* buffer, size_t size);
	bool WriteMemory(uint64_t address, void* buffer, size_t size);
	uint64_t AllocateMemory(size_t size, uint32_t protect);
	bool FreeMemory(uint64_t address);
	bool ChangeMemoryProtection(uint64_t address, size_t size, uint32_t new_protection, uint32_t* old_protection);
	uint64_t GetImageBase();
	vec_modules GetLoadedModules();
	uint64_t GetModuleExport(uint64_t module_base, const std::string& function_name);
	uint64_t GetModuleBase(const std::string& module_name);
	uint64_t GetIATAddress(uint64_t module_base, const std::string& import_module_name, const std::string& import_name);
	uint64_t MapModule(const std::string& module_path);
private:
	void RelocateImageByDelta(portable_executable::vec_relocs relocs, const uint64_t delta);
	bool ResolveImports(portable_executable::vec_imports imports);
	bool CallDllMain(uint64_t module_base, uint64_t entry_point_address);
private:
	uint32_t m_pid;
	std::string m_process_name;
	bool m_is_attached;
	vec_mapped_modules m_mapped_modules;
};