#include "utils.hpp"

bool utils::ReadFileToMemory(const std::string& file_path, std::vector<uint8_t>* out_buffer)
{
	std::ifstream file_ifstream(file_path, std::ios::binary);

	if (!file_ifstream)
		return false;

	out_buffer->assign((std::istreambuf_iterator<char>(file_ifstream)), std::istreambuf_iterator<char>());
	file_ifstream.close();

	return true;
}

uint32_t utils::GetProcessIdByName(const std::string &process_name)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (snapshot == INVALID_HANDLE_VALUE)
		return 0;

	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(snapshot, &processEntry))
	{
		CloseHandle(snapshot);
		return 0;
	}

	do
	{
		if (!process_name.compare(processEntry.szExeFile))
		{
			CloseHandle(snapshot);
			return processEntry.th32ProcessID;
		}
	} while (Process32Next(snapshot, &processEntry));

	CloseHandle(snapshot);
	return 0;
}

std::string utils::GetProcessNameById(uint32_t pid)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (snapshot == INVALID_HANDLE_VALUE)
		return "";

	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(snapshot, &processEntry))
	{
		CloseHandle(snapshot);
		return 0;
	}

	do
	{
		if (processEntry.th32ProcessID == pid)
		{
			CloseHandle(snapshot);
			return processEntry.szExeFile;
		}
	} while (Process32Next(snapshot, &processEntry));

	CloseHandle(snapshot);
	return "";
}

bool utils::ProcessExists(uint32_t pid)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (snapshot == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	PROCESSENTRY32 process_entry;
	process_entry.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(snapshot, &process_entry))
	{
		CloseHandle(snapshot);
		return false;
	}

	do
	{
		if (process_entry.th32ProcessID == pid)
		{
			return true;
		}
	} while (Process32Next(snapshot, &process_entry));

	CloseHandle(snapshot);
	return false;
}

bool utils::ProcessExists(const std::string& process_name)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (snapshot == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	PROCESSENTRY32 process_entry;
	process_entry.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(snapshot, &process_entry))
	{
		CloseHandle(snapshot);
		return false;
	}

	do
	{
		if (!process_name.compare(process_entry.szExeFile))
		{
			return true;
		}
	} while (Process32Next(snapshot, &process_entry));

	CloseHandle(snapshot);
	return false;
}

uint64_t utils::GetKernelModuleAddress(const std::string& module_name)
{
	void* buffer = nullptr;
	DWORD buffer_size = 0;

	NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);

	while (status == nt::STATUS_INFO_LENGTH_MISMATCH)
	{
		VirtualFree(buffer, 0, MEM_RELEASE);

		buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);
	}

	if (!NT_SUCCESS(status))
	{
		VirtualFree(buffer, 0, MEM_RELEASE);
		return 0;
	}

	const auto modules = static_cast<nt::PRTL_PROCESS_MODULES>(buffer);

	for (auto i = 0u; i < modules->NumberOfModules; ++i)
	{
		const std::string current_module_name = std::string(reinterpret_cast<char*>(modules->Modules[i].FullPathName) + modules->Modules[i].OffsetToFileName);

		if (!_stricmp(current_module_name.c_str(), module_name.c_str()))
		{
			const uint64_t result = reinterpret_cast<uint64_t>(modules->Modules[i].ImageBase);

			VirtualFree(buffer, 0, MEM_RELEASE);
			return result;
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);
	return 0;
}

DWORD utils::GetThreadIdFromProcessId(uint32_t process_id)
{
	HWND current_window = NULL;

	do
	{
		current_window = FindWindowEx(NULL, current_window, NULL, NULL);

		DWORD current_pid = 0;
		uint32_t thread_id = GetWindowThreadProcessId(current_window, &current_pid);

		if (current_pid == process_id)
			return thread_id;

	} while (current_window != NULL);

	return 0;
}
