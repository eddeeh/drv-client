#include "driver.hpp"
#include "utils.hpp"
#include "encryption.hpp"
#include <sstream>
#include "process.hpp"
#include <iomanip>

int main()
{
	Process process;
	std::string cmd_line;

	while (std::getline(std::cin, cmd_line))
	{
		std::istringstream iss(cmd_line);
		std::vector<std::string>args(std::istream_iterator<std::string>{ iss }, std::istream_iterator<std::string>());

		if (args.empty())
			continue;

		const std::string command = args[0];

		if (!command.compare("a"))
		{
			// ATTACH TO A PROCESS

			if (args.size() != 2)
			{
				std::cout << encryption::XorString("[-] invalid usage") << std::endl;
				continue;
			}

			const std::string attach_arg = args[1];
			/*
			if (std::experimental::filesystem::path(attach_arg).has_extension())
			{
				const std::string process_name = attach_arg;
				process.Attach(process_name);
			}
			else
			{
				const std::uint32_t pid = std::stoul(attach_arg);
				process.Attach(pid);
			}
			*/

			const std::string process_name = attach_arg;
			process.Attach(process_name);
		}
		else if (!command.compare("d"))
		{
			// DETACH FROM A PROCESS

			process.Deattach();
		}
		else if (!command.compare("db"))
		{
			// READ N BYTES

			if (args.size() != 3)
			{
				std::cout << encryption::XorString("[-] invalid usage") << std::endl;
				continue;
			}

			const uint64_t address = std::stoull(args[1], nullptr, 16);
			const size_t size = std::stoull(args[2]);

			size_t aligned_size = 0;

			if (!(size % 16))
				aligned_size = size;
			else
				aligned_size = (size / 16) * 16 + 16;

			auto buffer = new uint8_t[aligned_size];

			if (!process.ReadMemory(address, buffer, aligned_size))
			{
				std::cout << encryption::XorString("[-] failed to read address 0x") << reinterpret_cast<void*>(address) << std::endl;
				delete[] buffer;
				continue;
			}

			for (auto i = 0u; i <= aligned_size - 16; i += 16)
			{
				std::cout << std::setw(16) << std::setfill('0') << std::hex << address + i << '\t';

				for (auto j = 0u; j < 16; ++j)
				{
					std::cout << std::setw(2) << std::setfill('0') << std::hex << uint32_t(buffer[i + j]) << ' ';
				}

				std::cout << '\t';

				for (auto k = 0u; k < 16; ++k)
				{
					if (isprint(buffer[i + k]))
					{
						std::cout << std::dec << buffer[i + k];
					}
					else
					{
						std::cout << std::dec << '.';
					}
				}

				std::cout << std::endl;
			}

			delete[] buffer;
		}
		else if (!command.compare("dc"))
		{
			// READ N DWORD ADDRESSES

			if (args.size() != 3)
			{
				std::cout << encryption::XorString("[-] invalid usage") << std::endl;
				continue;
			}

			const uint64_t address = std::stoull(args[1], nullptr, 16);
			const size_t count = std::stoull(args[2]);

			const size_t size = count * 4;
			size_t aligned_size = 0;

			if (!(size % 16))
				aligned_size = size;
			else
				aligned_size = (size / 16) * 16 + 16;

			auto buffer = new uint8_t[aligned_size];

			if (!process.ReadMemory(address, buffer, aligned_size))
			{
				std::cout << encryption::XorString("[-] failed to read address 0x") << reinterpret_cast<void*>(address) << std::endl;
				delete[] buffer;
				continue;
			}

			for (auto i = 0u; i <= aligned_size - 16; i += 16)
			{
				std::cout << std::setw(16) << std::setfill('0') << std::hex << address + i << '\t';

				for (auto j = 0u; j < 16; j += 4)
				{
					std::cout << std::setw(8) << std::setfill('0') << std::hex << *reinterpret_cast<uint32_t*>(reinterpret_cast<uint64_t>(buffer) + i + j) << ' ';
				}

				std::cout << std::dec << std::endl;
			}

			delete[] buffer;
		}
		else if (!command.compare("dq"))
		{
			// READ N DWORD ADDRESSES

			if (args.size() != 3)
			{
				std::cout << encryption::XorString("[-] invalid usage") << std::endl;
				continue;
			}

			const uint64_t address = std::stoull(args[1], nullptr, 16);
			const size_t count = std::stoull(args[2]);

			const size_t size = count * 8;
			size_t aligned_size = 0;

			if (!(size % 16))
				aligned_size = size;
			else
				aligned_size = (size / 16) * 16 + 16;

			auto buffer = new uint8_t[aligned_size];

			if(!process.ReadMemory(address, buffer, aligned_size))
			{
				std::cout << encryption::XorString("[-] failed to read address 0x") << reinterpret_cast<void*>(address) << std::endl;
				delete[] buffer;
				continue;
			}

			for (auto i = 0u; i <= aligned_size - 16; i += 16)
			{
				std::cout << std::setw(16) << std::setfill('0') << std::hex << address + i << '\t';

				for (auto j = 0u; j < 16; j += 8)
				{
					std::cout << std::setw(16) << std::setfill('0') << std::hex << *reinterpret_cast<uint64_t*>(reinterpret_cast<uint64_t>(buffer) + i + j) << ' ';
				}

				std::cout << std::dec << std::endl;
			}

			delete[] buffer;
		}
		else if (!command.compare("eb"))
		{
			// WRITE BYTE	

			if (args.size() != 3)
			{
				std::cout << encryption::XorString("[-] invalid usage") << std::endl;
				continue;
			}

			const uint64_t address = std::stoull(args[1], nullptr, 16);
			uint8_t val = std::stoul(args[2], nullptr, 16);

			uint32_t new_protection = PAGE_EXECUTE_READWRITE, old_protection = 0;

			if (!process.ChangeMemoryProtection(address, sizeof(val), new_protection, &old_protection))
			{
				std::cout << encryption::XorString("[-] failed to change memory protection of address 0x") << reinterpret_cast<void*>(address) << std::endl;
				continue;
			}
			
			if (!process.WriteMemory(address, &val, sizeof(val)))
			{
				std::cout << encryption::XorString("[-] failed to write to address 0x") << reinterpret_cast<void*>(address) << std::endl;
				continue;
			}

			process.ChangeMemoryProtection(address, sizeof(val), old_protection, &new_protection);
		}
		else if (!command.compare("ed"))
		{
			// WRITE DWORD	

			if (args.size() != 3)
			{
				std::cout << encryption::XorString("[-] invalid usage") << std::endl;
				continue;
			}

			const uint64_t address = std::stoull(args[1], nullptr, 16);
			uint32_t val = std::stoul(args[2], nullptr, 16);

			uint32_t new_protection = PAGE_EXECUTE_READWRITE, old_protection = 0;

			if (!process.ChangeMemoryProtection(address, sizeof(val), new_protection, &old_protection))
			{
				std::cout << encryption::XorString("[-] failed to change memory protection of address 0x") << reinterpret_cast<void*>(address) << std::endl;
				continue;
			}

			if (!process.WriteMemory(address, &val, sizeof(val)))
			{
				std::cout << encryption::XorString("[-] failed to write to address 0x") << reinterpret_cast<void*>(address) << std::endl;
				continue;
			}

			process.ChangeMemoryProtection(address, sizeof(val), old_protection, &new_protection);
		}
		else if (!command.compare("eq"))
		{
			// WRITE QWORD	

			if (args.size() != 3)
			{
				std::cout << encryption::XorString("[-] invalid usage") << std::endl;
				continue;
			}

			const uint64_t address = std::stoull(args[1], nullptr, 16);
			uint64_t val = std::stoull(args[2], nullptr, 16);

			uint32_t new_protection = PAGE_EXECUTE_READWRITE, old_protection = 0;

			if(!process.ChangeMemoryProtection(address, sizeof(val), new_protection, &old_protection))
			{
				std::cout << encryption::XorString("[-] failed to change memory protection of address 0x") << reinterpret_cast<void*>(address) << std::endl;
				continue;
			}

			if(!process.WriteMemory(address, &val, sizeof(val)))
			{
				std::cout << encryption::XorString("[-] failed to write to address 0x") << reinterpret_cast<void*>(address) << std::endl;
				continue;
			}

			process.ChangeMemoryProtection(address, sizeof(val), old_protection, &new_protection);
		}
		else if (!command.compare("b"))
		{
			// GET IMAGE BASE	

			std::cout << std::setw(16) << std::setfill('0') << std::hex << process.GetImageBase() << std::endl;
		}
		else if (!command.compare("lm"))
		{
			// GET LOADED MODULES	

			for (const auto& [module_name, base] : process.GetLoadedModules())
			{
				std::cout << std::setw(16) << std::setfill('0') << std::hex << base << '\t' << std::dec << module_name << std::endl;
			}
		}
		else if (!command.compare("mb"))
		{
			// GET MODULE BASE	

			if (args.size() != 2)
			{
				std::cout << encryption::XorString("[-] invalid usage") << std::endl;
				continue;
			}

			const std::string module_name = args[1];
			const auto module_base = process.GetModuleBase(module_name);

			if (!module_base)
			{
				std::cout << encryption::XorString("[-] failed to get module base of ") << module_name << std::endl;
				continue;
			}

			std::cout << std::setw(16) << std::setfill('0') << std::hex << process.GetModuleBase(module_name) << std::dec << std::endl;
		}
		else if (!command.compare("me"))
		{
			// GET MODULE EXPORT	

			if (args.size() != 3)
			{
				std::cout << encryption::XorString("[-] invalid usage") << std::endl;
				continue;
			}

			const std::string export_name = args[2];
			uint64_t module_base = 0;

			if (std::experimental::filesystem::path(args[1]).has_extension())
			{
				module_base = process.GetModuleBase(args[1]);
				
				if (!module_base)
				{
					std::cout << encryption::XorString("[-] failed to get module base of ") << args[1] << std::endl;
					continue;
				}
			}
			else
			{
				module_base = std::stoull(args[1], nullptr, 16);
			}

			const uint64_t module_export = process.GetModuleExport(module_base, export_name);

			if (!module_export)
			{
				std::cout << encryption::XorString("[-] failed to get module base of ") << export_name << ' ' << args[1] << std::endl;
				continue;
			}

			std::cout << std::setw(16) << std::setfill('0') << std::hex << module_export << std::dec << std::endl;
		}
		else if (!command.compare("mm"))
		{
			// MANUAL MAP

			if (args.size() != 2)
			{
				std::cout << encryption::XorString("[-] invalid usage") << std::endl;
				continue;
			}

			const std::string path = args[1];
			
			if (!process.MapModule(path))
			{
				std::cout << encryption::XorString("[-] failed to manual map ") << path << std::endl;
			}
		}
		else
		{
			std::cout << encryption::XorString("[-] unknown command \"") << command << '\"' << std::endl;
		}
	}

}
