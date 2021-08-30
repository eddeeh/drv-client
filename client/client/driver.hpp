#pragma once
#pragma warning( disable : 4244 )
#include <Windows.h>
#include <stdint.h>
#include <string>
#include <filesystem>
#include <iostream>
#include <thread>
#include <chrono>
#include "nt.hpp"
#include "encryption.hpp"
#include "utils.hpp"
#pragma comment(lib, "user32.lib")

namespace driver
{
	enum DRIVER_OPERATION
	{
		IDLE,
		COPY_MEMORY,
		ALLOCATE_MEMORY,
		FREE_MEMORY,
		PROTECT_MEMORY,
		GET_PROCESS_PEB_BASE
	};


	typedef struct _IO_BUFFER
	{
		NTSTATUS status;
		NTSTATUS driver_operation_status;
		DRIVER_OPERATION driver_operation;
		uint64_t result;
		uint32_t ul1;
		uint32_t ul2;
		uint64_t ull1;
		uint64_t ull2;
		SIZE_T size;
	}IO_BUFFER, * PIO_BUFFER;
	
	NTSTATUS CallDriverControl(PIO_BUFFER io_buffer);
	
	bool ReadMemory(uint32_t process_id, uint64_t address, void* buffer, size_t size);
	bool WriteMemory(uint32_t process_id, uint64_t address, void* buffer, size_t size);
	uint64_t AllocateMemory(uint32_t process_id, size_t size, uint32_t protect);
	bool FreeMemory(uint32_t process_id, uint64_t address);
	bool ChangeMemoryProtection(uint32_t process_id, uint64_t address, size_t size, uint32_t new_protection, uint32_t* old_protection);
	uint64_t GetPebBase(uint32_t process_id);
}