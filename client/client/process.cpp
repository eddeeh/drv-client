#include "process.hpp"

bool Process::Attach(uint32_t pid)
{
	Deattach();

	m_pid = pid;

	if (!utils::ProcessExists(m_pid))
	{
		std::cerr << encryption::XorString("[-] Process doesn't exist") << std::endl;
		return false;
	}

	m_process_name = utils::GetProcessNameById(m_pid);
	
	m_is_attached = true;
	return true;
}

bool Process::Attach(std::string process_name)
{
	Deattach();

	m_process_name = process_name;

	if (!utils::ProcessExists(m_process_name))
	{
		std::cerr << encryption::XorString("[-] Process doesn't exist") << std::endl;
		return false;
	}

	m_pid = utils::GetProcessIdByName(m_process_name);

	if (!m_pid)
	{
		std::cerr << encryption::XorString("[-] Failed to get process id") << std::endl;
		return false;
	}
	
	m_is_attached = true;
	return true;
}

bool Process::IsAttached()
{
	return m_is_attached;
}

void Process::Deattach()
{
	m_pid = 0;
	m_process_name.clear();
	m_mapped_modules.clear();
	m_is_attached = false;
}

bool Process::ReadMemory(uint64_t address, void* buffer, size_t size)
{
	if (!m_is_attached)
	{
		return false;
	}

	return driver::ReadMemory(m_pid, address, buffer, size);
}

bool Process::WriteMemory(uint64_t address, void* buffer, size_t size)
{
	if (!m_is_attached)
	{
		return false;
	}

	return driver::WriteMemory(m_pid, address, buffer, size);
}

uint64_t Process::AllocateMemory(size_t size, uint32_t protect)
{
	if (!m_is_attached)
	{
		return false;
	}

	return driver::AllocateMemory(m_pid, size, protect);
}
bool Process::FreeMemory(uint64_t address)
{
	if (!m_is_attached)
	{
		return false;
	}

	return driver::FreeMemory(m_pid, address);
}

bool Process::ChangeMemoryProtection(uint64_t address, size_t size, uint32_t new_protection, uint32_t* old_protection)
{
	if (!m_is_attached)
	{
		return false;
	}

	return driver::ChangeMemoryProtection(m_pid, address, size, new_protection, old_protection);
}

uint64_t Process::GetImageBase()
{
	if (!m_is_attached)
	{
		return false;
	}

	nt::PEB peb = { 0 };

	const uint64_t peb_base = driver::GetPebBase(m_pid);

	if (!peb_base)
	{
		std::cerr << encryption::XorString("[-] Failed to get PEB base of ") << m_pid << std::endl;
		return 0;
	}

	if (!driver::ReadMemory(m_pid, peb_base, &peb, sizeof(peb)))
	{
		std::cerr << encryption::XorString("[-] Failed to read PEB of ") << m_pid << std::endl;
		return 0;
	}

	return reinterpret_cast<uint64_t>(peb.ImageBaseAddress);
}

vec_modules Process::GetLoadedModules()
{
	if (!m_is_attached)
	{
		return {};
	}

	vec_modules result = {};
	
	nt::PEB peb = { 0 };

	const uint64_t peb_base = driver::GetPebBase(m_pid);

	if (!peb_base)
	{
		std::cout << encryption::XorString("[-] Failed to get PEB base of ") << m_pid << std::endl;
		return {};
	}

	if (!ReadMemory(peb_base, &peb, sizeof(peb)))
	{
		std::cout << encryption::XorString("[-] Failed to read PEB of ") << m_pid << std::endl;
		return {};
	}

	nt::PEB_LDR_DATA ldr_data;

	if (!ReadMemory(reinterpret_cast<uint64_t>(peb.LoaderData), &ldr_data, sizeof(ldr_data)))
	{
		return {};
	}

	const LIST_ENTRY* flink_start = ldr_data.InLoadOrderModuleList.Flink;
	LIST_ENTRY* flink_current = ldr_data.InLoadOrderModuleList.Flink;

	nt::LDR_MODULE current_module = { 0 };

	do
	{
		if (!ReadMemory(reinterpret_cast<uint64_t>(flink_current), &current_module, sizeof(current_module)))
		{
			return result;
		}

		wchar_t buffer[MAX_PATH] = { 0 };

		if (!ReadMemory(reinterpret_cast<uint64_t>(current_module.BaseDllName.Buffer), buffer, current_module.BaseDllName.Length))
		{
			return result;
		}

		std::wstring wcurrent_module_name = buffer;
		std::string current_module_name = std::string(wcurrent_module_name.begin(), wcurrent_module_name.end());

		Module mod = { current_module_name, reinterpret_cast<uint64_t>(current_module.BaseAddress) };
		result.push_back(mod);

		flink_current = current_module.InLoadOrderModuleList.Flink;

	} while (flink_current != flink_start);
	   	  
	return result;
}

uint64_t Process::GetModuleExport(uint64_t module_base, const std::string& function_name)
{
	if (!m_is_attached)
	{
		return 0;
	}

	IMAGE_DOS_HEADER dos_header = { 0 };
	IMAGE_NT_HEADERS64 nt_headers = { 0 };

	if (!ReadMemory(module_base, &dos_header, sizeof(dos_header)) || dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
		!ReadMemory(module_base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers)) || nt_headers.Signature != IMAGE_NT_SIGNATURE)
		return 0;

	const auto export_base = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	const auto export_base_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	if (!export_base)
		return 0;

	const auto export_data = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(VirtualAlloc(nullptr, export_base_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (!ReadMemory(module_base + export_base, export_data, export_base_size))
	{
		VirtualFree(export_data, 0, MEM_RELEASE);
		return 0;
	}

	const auto delta = reinterpret_cast<uint64_t>(export_data) - export_base;

	const auto name_table = reinterpret_cast<uint32_t*>(export_data->AddressOfNames + delta);
	const auto ordinal_table = reinterpret_cast<uint16_t*>(export_data->AddressOfNameOrdinals + delta);
	const auto function_table = reinterpret_cast<uint32_t*>(export_data->AddressOfFunctions + delta);

	for (auto i = 0u; i < export_data->NumberOfNames; ++i)
	{
		const std::string current_function_name = std::string(reinterpret_cast<char*>(name_table[i] + delta));

		if (!_stricmp(current_function_name.c_str(), function_name.c_str()))
		{
			const auto current_ordinal_ = ordinal_table[i];
			const auto current_address = module_base + function_table[current_ordinal_];

			if (current_address >= module_base + export_base && current_address <= module_base + export_base + export_base_size)
			{
				char buffer[MAX_PATH];
				ReadMemory(current_address, buffer, sizeof(buffer));

				const std::string forwaded_name(buffer);

				const std::string forwaded_module_name = forwaded_name.substr(0, forwaded_name.find(".")) + encryption::XorString(".dll");
				const std::string forwaded_function_name = forwaded_name.substr(forwaded_name.find(".") + 1, forwaded_function_name.npos);

				VirtualFree(export_data, 0, MEM_RELEASE);
				return GetModuleExport(GetModuleBase(forwaded_module_name), forwaded_function_name);
			}

			VirtualFree(export_data, 0, MEM_RELEASE);
			return current_address;
		}
	}

	VirtualFree(export_data, 0, MEM_RELEASE);
	return 0;
}

uint64_t Process::GetModuleBase(const std::string& module_name)
{
	if (!m_is_attached)
	{
		return 0;
	}

	nt::PEB peb = { 0 };

	const uint64_t peb_base = driver::GetPebBase(m_pid);

	if (!peb_base)
	{
		std::cout << encryption::XorString("[-] Failed to get PEB base of ") << m_pid << std::endl;
		return false;
	}

	if (!ReadMemory(peb_base, &peb, sizeof(peb)))
	{
		std::cout << encryption::XorString("[-] Failed to read PEB of ") << m_pid << std::endl;
		return false;
	}

	nt::PEB_LDR_DATA ldr_data;

	if (!ReadMemory(reinterpret_cast<uint64_t>(peb.LoaderData), &ldr_data, sizeof(ldr_data)))
		return 0;

	const LIST_ENTRY* flink_start = ldr_data.InLoadOrderModuleList.Flink;
	LIST_ENTRY* flink_current = ldr_data.InLoadOrderModuleList.Flink;

	nt::LDR_MODULE current_module = { 0 };

	do
	{
		if (!ReadMemory(reinterpret_cast<uint64_t>(flink_current), &current_module, sizeof(current_module)))
			return 0;

		wchar_t buffer[MAX_PATH] = { 0 };

		if (!ReadMemory(reinterpret_cast<uint64_t>(current_module.BaseDllName.Buffer), buffer, current_module.BaseDllName.Length))
			return false;

		std::wstring wcurrent_module_name = buffer;
		std::string current_module_name = std::string(wcurrent_module_name.begin(), wcurrent_module_name.end());

		if (!_stricmp(current_module_name.c_str(), module_name.c_str()))
			return reinterpret_cast<uint64_t>(current_module.BaseAddress);

		flink_current = current_module.InLoadOrderModuleList.Flink;

	} while (flink_current != flink_start);

	return 0;
}

uint64_t Process::GetIATAddress(uint64_t module_base, const std::string& import_module_name, const std::string& import_name)
{
	if (!m_is_attached)
	{
		return 0;
	}

	IMAGE_DOS_HEADER dos_header = { 0 };
	IMAGE_NT_HEADERS64 nt_headers = { 0 };

	if (!ReadMemory(module_base, &dos_header, sizeof(dos_header)) || dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
		!ReadMemory(module_base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers)) || nt_headers.Signature != IMAGE_NT_SIGNATURE)
		return 0;

	const uint64_t import_directory_entry = module_base + nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	const uint32_t import_directory_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

	auto buffer = VirtualAlloc(nullptr, import_directory_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!ReadMemory(import_directory_entry, buffer, import_directory_size))
	{
		VirtualFree(buffer, 0, MEM_RELEASE);
		return 0;
	}

	auto current_import_descriptor = static_cast<PIMAGE_IMPORT_DESCRIPTOR>(buffer);

	while (current_import_descriptor->FirstThunk)
	{
		char current_import_module_name[MAX_PATH] = { 0 };

		if (!ReadMemory(module_base + current_import_descriptor->Name, current_import_module_name, sizeof(current_import_module_name)))
		{
			VirtualFree(buffer, 0, MEM_RELEASE);
			return 0;
		}

		if (_stricmp(import_module_name.c_str(), current_import_module_name))
		{
			++current_import_descriptor;
			continue;
		}

		auto buffer2 = VirtualAlloc(nullptr, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!ReadMemory(module_base + current_import_descriptor->OriginalFirstThunk, buffer2, 0x2000))
		{
			VirtualFree(buffer2, 0, MEM_RELEASE);
			VirtualFree(buffer, 0, MEM_RELEASE);

			return 0;
		}

		auto current_original_first_thunk = static_cast<PIMAGE_THUNK_DATA64>(buffer2);
		auto function_index = 0u;

		while (current_original_first_thunk->u1.Function)
		{
			auto thunk_data = static_cast<PIMAGE_IMPORT_BY_NAME>(VirtualAlloc(nullptr, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

			if (!ReadMemory(module_base + current_original_first_thunk->u1.AddressOfData, thunk_data, 0x2000))
			{
				VirtualFree(thunk_data, 0, MEM_RELEASE);
				VirtualFree(buffer2, 0, MEM_RELEASE);
				VirtualFree(buffer, 0, MEM_RELEASE);

				return 0;
			}

			if (!_stricmp(import_name.c_str(), thunk_data->Name))
			{
				VirtualFree(thunk_data, 0, MEM_RELEASE);
				break;
			}

			VirtualFree(thunk_data, 0, MEM_RELEASE);

			++current_original_first_thunk;
			++function_index;
		}

		VirtualFree(buffer2, 0, MEM_RELEASE);

		if (!function_index)
		{
			VirtualFree(buffer, 0, MEM_RELEASE);
			return 0;
		}

		uint32_t first_thunk = current_import_descriptor->FirstThunk;
		VirtualFree(buffer, 0, MEM_RELEASE);

		return reinterpret_cast<uint64_t>(function_index + reinterpret_cast<void**>(module_base + first_thunk));
	}

	VirtualFree(buffer, 0, MEM_RELEASE);
	return 0;
}

uint64_t Process::MapModule(const std::string& module_path)
{
	if (!m_is_attached)
	{
		return 0;
	}

	if (!std::experimental::filesystem::exists(module_path))
	{
		std::cout << encryption::XorString("[-] ") << module_path << encryption::XorString(" doensn't exist") << std::endl;
		return false;
	}

	std::cout << encryption::XorString("Mapping module ") << module_path << std::endl;

	const std::string module_name = std::experimental::filesystem::path(module_path).filename().string();
	std::vector<uint8_t>raw_image = { 0 };

	if (!utils::ReadFileToMemory(module_path, &raw_image))
	{
		std::cout << encryption::XorString("[-] Failed to read the module to memory") << std::endl;
		return false;
	}

	const PIMAGE_NT_HEADERS64 nt_headers = portable_executable::GetNtHeaders(raw_image.data());

	if (!nt_headers)
	{
		std::cout << encryption::XorString("[-] Invalid image format") << std::endl;
		return 0;
	}

	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		std::cout << encryption::XorString("[-] Image is not 64 bit") << std::endl;
		return 0;
	}

	const uint32_t image_size = nt_headers->OptionalHeader.SizeOfImage;

	const auto local_image_base = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (!local_image_base)
	{
		std::cout << encryption::XorString("[-] Failed to allocate local image base") << std::endl;
		return 0;
	}

	const uint64_t remote_image_base = AllocateMemory(image_size, PAGE_EXECUTE_READWRITE);

	if (!remote_image_base)
	{
		std::cout << encryption::XorString("[-] Failed to allocate memory for image in remote process") << std::endl;

		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return 0;
	}

	std::cout << encryption::XorString("[+] Image base of ") << module_name << encryption::XorString(" has been allocated at 0x") << reinterpret_cast<void*>(remote_image_base) << std::endl;

	// Copy image headers

	memcpy(local_image_base, raw_image.data(), nt_headers->OptionalHeader.SizeOfHeaders);

	// Copy image sections

	const PIMAGE_SECTION_HEADER image_sections = IMAGE_FIRST_SECTION(nt_headers);

	for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i)
	{
		auto local_section = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(local_image_base) + image_sections[i].VirtualAddress);
		memcpy(local_section, reinterpret_cast<void*>(reinterpret_cast<uint64_t>(raw_image.data()) + image_sections[i].PointerToRawData), image_sections[i].SizeOfRawData);
	}

	// Resolve relocs and imports

	RelocateImageByDelta(portable_executable::GetRelocs(local_image_base), remote_image_base - nt_headers->OptionalHeader.ImageBase);

	if (!ResolveImports(portable_executable::GetImports(local_image_base)))
	{
		std::cout << encryption::XorString("[-] Failed to resolve imports") << std::endl;

		VirtualFree(local_image_base, 0, MEM_RELEASE);
		FreeMemory(remote_image_base);

		return 0;
	}

	// Write fixed image in remote process

	if (!WriteMemory(remote_image_base, local_image_base, image_size))
	{
		std::cout << encryption::XorString("[-] Failed to write fixed image in remote process") << std::endl;

		VirtualFree(local_image_base, 0, MEM_RELEASE);
		FreeMemory(remote_image_base);

		return 0;
	}

	VirtualFree(local_image_base, 0, MEM_RELEASE);

	// Set memory protection

	for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i)
	{
		uint32_t old_protection = 0;

		if (!ChangeMemoryProtection(remote_image_base + image_sections[i].VirtualAddress, image_sections[i].SizeOfRawData,
			portable_executable::GetSectionProtection(image_sections[i].Characteristics), &old_protection))
		{
			std::cout << image_sections[i].SizeOfRawData << std::endl;
			std::cout << encryption::XorString("[-] Failed to set memory protection") << std::endl;
			FreeMemory(remote_image_base);

			return 0;
		}
	}

	// Call entry point

	const uint64_t address_of_entry_point = remote_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

	std::cout << encryption::XorString("Calling entry point of ") << module_name << encryption::XorString(" 0x") << reinterpret_cast<void*>(address_of_entry_point) << std::endl;

	if (!CallDllMain(remote_image_base, address_of_entry_point))
	{
		std::cout << encryption::XorString("[-] Failed to call DllMain") << std::endl;
		FreeMemory(remote_image_base);

		return 0;
	}

	MappedModule mapped_module = { module_name, remote_image_base };
	m_mapped_modules.push_back(mapped_module);

	return remote_image_base;
}

void Process::RelocateImageByDelta(portable_executable::vec_relocs relocs, const uint64_t delta)
{
	for (const auto& current_reloc : relocs)
	{
		for (auto i = 0u; i < current_reloc.count; ++i)
		{
			const uint16_t type = current_reloc.item[i] >> 12;
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				* reinterpret_cast<uint64_t*>(current_reloc.address + offset) += delta;
		}
	}
}

bool Process::ResolveImports(portable_executable::vec_imports imports)
{
	for (const auto& current_import : imports)
	{
		char module_path[MAX_PATH];

		if (!GetModuleFileName(LoadLibrary(current_import.module_name.c_str()), module_path, sizeof(module_path)))
		{
			std::cout << encryption::XorString("[-] Failed to get location of dependency ") << current_import.module_name << std::endl;
			return false;
		}

		const std::string resolved_module_name = std::experimental::filesystem::path(module_path).filename().string();
		uint64_t module_base = 0;

		for (const auto& mapped_module : m_mapped_modules)
		{
			if (!resolved_module_name.compare(mapped_module.module_name))
			{
				module_base = mapped_module.module_base;
				break;
			}
		}

		if (!module_base)
		{
			module_base = GetModuleBase(resolved_module_name);

			if (!module_base)
			{
				module_base = MapModule(module_path);

				if (!module_base)
				{
					std::cout << encryption::XorString("[-] Failed to load dependency ") << current_import.module_name << " (" << module_path << ")" << std::endl;
					return false;
				}
			}
		}

		for (auto& current_function_data : current_import.function_datas)
		{
			const uint64_t function_address = GetModuleExport(module_base, current_function_data.name);

			if (!function_address)
			{
				std::cout << encryption::XorString("[-] Failed to resolve import: ") << current_import.module_name << '!' << current_function_data.name << std::endl;
				return false;
			}

			//std::cout << encryption::XorString("[?] Export ") << resolved_module_name << '!' << current_function_data.name << encryption::XorString(": 0x") << reinterpret_cast<void*>(function_address) << std::endl;

			*current_function_data.address = function_address;
		}
	}

	return true;
}

bool Process::CallDllMain(uint64_t module_base, uint64_t entry_point_address)
{
	const uint64_t NtUserGetMessage = GetModuleExport(GetModuleBase(encryption::XorString("win32u.dll")), encryption::XorString("NtUserGetMessage"));

	if (!NtUserGetMessage)
	{
		std::cout << encryption::XorString("[-] Failed to get export win32u!NtUserGetMessage") << std::endl;
		return false;
	}

	const uint64_t function_iat_address = GetIATAddress(GetModuleBase(encryption::XorString(("user32.dll"))), encryption::XorString("win32u.dll"), encryption::XorString("NtUserGetMessage"));

	if (!function_iat_address)
	{
		std::cout << encryption::XorString("[-] Failed to get IAT address of NtUserGetMessage") << std::endl;
		return false;
	}

	uint8_t shellcode[] = {
		0x48, 0x83, 0xEC, 0x28,											// sub rsp, 0x28
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// mov rax, 0x0000000000000000
		0x48, 0xBF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// mov rdi, 0x0000000000000000
		0x48, 0x89, 0x38,												// mov [rax], rdi
		0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// mov rcx, 0x0000000000000000
		0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,						// mov rdx, 0x01
		0x4D, 0x31, 0xC0,												// xor r8, r8
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// mov rax, 0x0000000000000000
		0xFF, 0xD0,														// call rax
		0x48, 0x83, 0xC4, 0x28,											// add rsp, 0x28
		0xC3															// ret													
	};

	*reinterpret_cast<uint64_t*>(shellcode + 0x6) = function_iat_address;
	*reinterpret_cast<uint64_t*>(shellcode + 0x10) = NtUserGetMessage;
	*reinterpret_cast<uint64_t*>(shellcode + 0x1D) = module_base;
	*reinterpret_cast<uint64_t*>(shellcode + 0x31) = entry_point_address;

	uint64_t remote_shellcode = AllocateMemory(sizeof(shellcode), PAGE_EXECUTE_READWRITE);

	if (!remote_shellcode)
		return false;

	if (!WriteMemory(remote_shellcode, shellcode, sizeof(shellcode)))
	{
		FreeMemory(remote_shellcode);
		return false;
	}

	uint32_t old_protection = 0;
	uint32_t new_protection = PAGE_READWRITE;

	if (!ChangeMemoryProtection(function_iat_address, sizeof(uint64_t), new_protection, &old_protection))
	{
		FreeMemory(remote_shellcode);
		return false;
	}

	if (!WriteMemory(function_iat_address, &remote_shellcode, sizeof(remote_shellcode)))
	{
		ChangeMemoryProtection(function_iat_address, sizeof(uint64_t), old_protection, &new_protection);
		FreeMemory(remote_shellcode);
		return false;
	}

	const auto thread_id = utils::GetThreadIdFromProcessId(m_pid);
	const bool result = PostThreadMessageW(thread_id, WM_USER + 400, 0, 0) != 0;

	Sleep(200);

	ChangeMemoryProtection(function_iat_address, sizeof(uint64_t), old_protection, &new_protection);
	FreeMemory(remote_shellcode);

	return result;
}