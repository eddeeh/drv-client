#pragma once
#include <Windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)

namespace nt
{
	constexpr auto STATUS_SUCCESS = 0;

	constexpr auto SE_DEBUG_PRIVILEGE = 20;
	constexpr auto STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
	
	constexpr auto SystemModuleInformation = 11;

	typedef struct _PEB_LDR_DATA {
		ULONG                   Length;
		BOOLEAN                 Initialized;
		PVOID                   SsHandle;
		LIST_ENTRY              InLoadOrderModuleList;
		LIST_ENTRY              InMemoryOrderModuleList;
		LIST_ENTRY              InInitializationOrderModuleList;
	} PEB_LDR_DATA, *PPEB_LDR_DATA;

	typedef struct _LDR_MODULE {
		LIST_ENTRY              InLoadOrderModuleList;
		LIST_ENTRY              InMemoryOrderModuleList;
		LIST_ENTRY              InInitializationOrderModuleList;
		PVOID                   BaseAddress;
		PVOID                   EntryPoint;
		ULONG                   SizeOfImage;
		UNICODE_STRING          FullDllName;
		UNICODE_STRING          BaseDllName;
		ULONG                   Flags;
		SHORT                   LoadCount;
		SHORT                   TlsIndex;
		LIST_ENTRY              HashTableEntry;
		ULONG                   TimeDateStamp;
	} LDR_MODULE, *PLDR_MODULE;

	typedef struct _PEB {
		BOOLEAN                 InheritedAddressSpace;
		BOOLEAN                 ReadImageFileExecOptions;
		BOOLEAN                 BeingDebugged;
		BOOLEAN                 Spare;
		HANDLE                  Mutant;
		PVOID                   ImageBaseAddress;
		PPEB_LDR_DATA           LoaderData;
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
		PVOID                   SubSystemData;
		PVOID                   ProcessHeap;
		PVOID                   FastPebLock;
		PVOID	                FastPebLockRoutine;
		PVOID			        FastPebUnlockRoutine;
		ULONG                   EnvironmentUpdateCount;
		PVOID*                  KernelCallbackTable;
		PVOID                   EventLogSection;
		PVOID                   EventLog;
		PVOID					FreeList;
		ULONG                   TlsExpansionCounter;
		PVOID                   TlsBitmap;
		ULONG                   TlsBitmapBits[0x2];
		PVOID                   ReadOnlySharedMemoryBase;
		PVOID                   ReadOnlySharedMemoryHeap;
		PVOID*                  ReadOnlyStaticServerData;
		PVOID                   AnsiCodePageData;
		PVOID                   OemCodePageData;
		PVOID                   UnicodeCaseTableData;
		ULONG                   NumberOfProcessors;
		ULONG                   NtGlobalFlag;
		BYTE                    Spare2[0x4];
		LARGE_INTEGER           CriticalSectionTimeout;
		ULONG                   HeapSegmentReserve;
		ULONG                   HeapSegmentCommit;
		ULONG                   HeapDeCommitTotalFreeThreshold;
		ULONG                   HeapDeCommitFreeBlockThreshold;
		ULONG                   NumberOfHeaps;
		ULONG                   MaximumNumberOfHeaps;
		PVOID*                  *ProcessHeaps;
		PVOID                   GdiSharedHandleTable;
		PVOID                   ProcessStarterHelper;
		PVOID                   GdiDCAttributeList;
		PVOID                   LoaderLock;
		ULONG                   OSMajorVersion;
		ULONG                   OSMinorVersion;
		ULONG                   OSBuildNumber;
		ULONG                   OSPlatformId;
		ULONG                   ImageSubSystem;
		ULONG                   ImageSubSystemMajorVersion;
		ULONG                   ImageSubSystemMinorVersion;
		ULONG                   GdiHandleBuffer[0x22];
		ULONG                   PostProcessInitRoutine;
		ULONG                   TlsExpansionBitmap;
		BYTE                    TlsExpansionBitmapBits[0x80];
		ULONG                   SessionId;
	} PEB, *PPEB;

	typedef struct _RTL_PROCESS_MODULE_INFORMATION
	{
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[256];
	} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

	typedef struct _RTL_PROCESS_MODULES
	{
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;
}