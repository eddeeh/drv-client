#include "driver.hpp"

NTSTATUS driver::CallDriverControl(PIO_BUFFER io_buffer)
{
	using NtUserGetAutoRotationStateFn = bool(__stdcall*)(PIO_BUFFER);
	const auto NtUserGetAutoRotationState = reinterpret_cast<NtUserGetAutoRotationStateFn>(GetProcAddress(LoadLibrary(encryption::XorString("win32u.dll")), encryption::XorString("NtUserGetAutoRotationState")));

	NtUserGetAutoRotationState(io_buffer);
	
	if (!NT_SUCCESS(io_buffer->status))
		return STATUS_UNSUCCESSFUL;

	return io_buffer->driver_operation_status;
}

bool driver::ReadMemory(uint32_t process_id, uint64_t address, void* buffer, size_t size)
{
	IO_BUFFER io_buffer = { 0 };

	io_buffer.driver_operation = COPY_MEMORY;
	io_buffer.ul1 = process_id;							// source process id
	io_buffer.ull1 = address;								// source address
	io_buffer.ul2 = GetCurrentProcessId();					// target process id
	io_buffer.ull2 = reinterpret_cast<uint64_t>(buffer);	// target address
	io_buffer.size = size;
	
	return NT_SUCCESS(CallDriverControl(&io_buffer));
}

bool driver::WriteMemory(uint32_t process_id, uint64_t address, void* buffer, size_t size)
{
	IO_BUFFER io_buffer = { 0 };

	io_buffer.driver_operation = COPY_MEMORY;
	io_buffer.ul1 = GetCurrentProcessId();					// source process id
	io_buffer.ull1 = reinterpret_cast<uint64_t>(buffer);	// source address
	io_buffer.ul2 = process_id;							// target process id
	io_buffer.ull2 = address;								// target address
	io_buffer.size = size;
	
	return NT_SUCCESS(CallDriverControl(&io_buffer));
}

uint64_t driver::AllocateMemory(uint32_t process_id, size_t size, uint32_t protect)
{
	IO_BUFFER io_buffer = { 0 }; 
	
	io_buffer.driver_operation = ALLOCATE_MEMORY;
	io_buffer.ul1 = process_id;
	io_buffer.size = size;
	io_buffer.ul2 = protect;

	if (!NT_SUCCESS(CallDriverControl(&io_buffer)))
		return 0;

	return io_buffer.result;
}

bool driver::FreeMemory(uint32_t process_id, uint64_t address)
{
	IO_BUFFER io_buffer = { 0 };

	io_buffer.driver_operation = FREE_MEMORY;
	io_buffer.ul1 = process_id;
	io_buffer.ull1 = address;

	return NT_SUCCESS(CallDriverControl(&io_buffer));
}

bool driver::ChangeMemoryProtection(uint32_t process_id, uint64_t address, size_t size, uint32_t new_protection, uint32_t* old_protection)
{
	IO_BUFFER io_buffer = { 0 }; 
	
	io_buffer.driver_operation = PROTECT_MEMORY;
	io_buffer.ul1 = process_id;
	io_buffer.ull1 = address;
	io_buffer.size = size;
	io_buffer.ul2 = new_protection;

	if (!NT_SUCCESS(CallDriverControl(&io_buffer)))
		return false;

	*old_protection = io_buffer.result;
	return true;
}

uint64_t driver::GetPebBase(uint32_t process_id)
{
	IO_BUFFER io_buffer = { 0 }; 
	
	io_buffer.driver_operation = GET_PROCESS_PEB_BASE;
	io_buffer.ul1 = process_id;

	if (!NT_SUCCESS(CallDriverControl(&io_buffer)))
		return 0;

	return io_buffer.result;
}