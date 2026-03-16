#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <bcrypt.h>
#include <vector>
#include <openssl/sha.h>

using  querySystemInfo = NTSTATUS(__stdcall*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

static querySystemInfo systemInfo = (querySystemInfo)(GetProcAddress)((LoadLibraryA)(("Ntdll.dll")), ("NtQuerySystemInformation"));

using fnNtReadVirtualMemory = NTSTATUS(__stdcall*)(HANDLE, PVOID, PVOID, ULONG, PULONG);
using fnNtWriteVirtualMemory = NTSTATUS(__stdcall*)(HANDLE, PVOID, PVOID, ULONG, PULONG);

inline auto NtReadVirtualMemory = (fnNtReadVirtualMemory)(GetProcAddress)((LoadLibraryA)(("Ntdll.dll")), ("NtReadVirtualMemory"));

inline auto NtWriteVirtualMemory = (fnNtWriteVirtualMemory)(GetProcAddress)((LoadLibraryA)(("Ntdll.dll")), ("NtWriteVirtualMemory"));




ULONG getProcess(const wchar_t* processName)
{
	ULONG pid{};
	ULONG bytes{};
	auto status = systemInfo(SystemProcessInformation, nullptr, bytes, &bytes);
	PSYSTEM_PROCESS_INFORMATION pProcessInfo;
	do
	{
		pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)(malloc(bytes));
		status = systemInfo(SystemProcessInformation, (PVOID)pProcessInfo, bytes, &bytes);
	} while (!NT_SUCCESS(status));

	do
	{
		pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)pProcessInfo + pProcessInfo->NextEntryOffset);
	} while (wcscmp(processName, pProcessInfo->ImageName.Buffer) != 0 && pProcessInfo->NextEntryOffset != 0);
	if (wcscmp(processName, pProcessInfo->ImageName.Buffer) == 0)
	{
		pid = (ULONG)pProcessInfo->UniqueProcessId;
	}
	pProcessInfo = nullptr;

	return pid;
}

inline HANDLE hProcess = 0;
inline ULONGLONG moduleBase = 0;
inline ULONG processId = 0;
inline SIZE_T module_size = 0;
template<typename T> static inline T read(ULONGLONG address,SIZE_T size) {
	T buffer;
	NtReadVirtualMemory(hProcess, reinterpret_cast<PVOID>(address), &buffer, size, NULL);

	return buffer;
}

template<typename T> static void write(ULONGLONG address, T* Value) {

    NtWriteVirtualMemory(hProcess, reinterpret_cast<PVOID>(address), (PVOID)&Value, sizeof(T), NULL);
}
static inline bool read_buffer(uint64_t address, void* buffer, size_t size)
{
	ULONG bytes_read = 0;
	NtReadVirtualMemory(hProcess, reinterpret_cast<PVOID>(address), buffer, size, &bytes_read);
	return bytes_read == size;
}
ULONGLONG getModule(const char* moduleName)
{
	ULONGLONG mod{};
	auto tool = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
	MODULEENTRY32 modEntry;
	modEntry.dwSize = sizeof(modEntry);
	if (Module32First(tool, &modEntry))
	{
		do
		{
			if (_stricmp(modEntry.szModule, moduleName) == 0)
			{
				mod = (ULONGLONG)modEntry.modBaseAddr;
				module_size = modEntry.modBaseSize;
			}
		} while (Module32Next(tool, &modEntry) && mod == 0);
	}
	CloseHandle(tool);
	return mod;


}

bool read_buffer_wrapper(uintptr_t adress,std::vector<uint8_t> data, SIZE_T size)
{
	if (!read_buffer(adress, data.data(), module_size))
	{
		printf("Reading module data failed\n");
		return 0;
	};
	return true;
}

PIMAGE_NT_HEADERS get_headers(void* data)
{

	PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(data);
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("Invalid DOS header\n");
		return nullptr;
	}
	return reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uintptr_t>(data) + dos_header->e_lfanew);
}

PIMAGE_SECTION_HEADER get_section_by_name(PIMAGE_NT_HEADERS nt_headers, const char* section_name) {
	auto first_section = IMAGE_FIRST_SECTION(nt_headers);
	for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
	{
		auto section = &first_section[i];
		if (strncmp((char*)section->Name, section_name, IMAGE_SIZEOF_SHORT_NAME) == 0)
		{
			return section;
		}
	}
	return nullptr;
}

std::vector<uint8_t> generate_SHA256(const std::vector<uint8_t>& data)
{
	std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
	SHA256(data.data(), data.size(), hash.data());
	return hash;
}

bool inicialite()
{
	processId = getProcess(L"FiveM_GameProcess.exe");
	if (!processId)
	{
		printf("Error finding target process\n");
		return 0;
	}
	moduleBase = getModule("FiveM_GameProcess.exe");
	if (!moduleBase)
	{
		printf("Error locanting the module base\n");
		return 0;
	}
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, processId);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		printf("Failed to open target process\n");
		return 0;
	}
	return true;
}

struct CodeCave
{
	uintptr_t addr; SIZE_T size;
};

std::vector<CodeCave> find_codecave(void* data, SIZE_T size)
{
	std::vector<CodeCave> final_result;
	BYTE* bytes = static_cast<BYTE*>(data);

	SIZE_T i = 0;
	while (i < size)
	{
		std::vector<uint8_t> codecave;

		while (i < size && bytes[i] == 0)
		{
			codecave.push_back(bytes[i]);
			++i;
		}
		const SIZE_T MIN_CAVE_SIZE = 100;
		if (!codecave.empty() && codecave.size() >= MIN_CAVE_SIZE)
		{
			CodeCave cv{ i - codecave.size(), codecave.size() };
			final_result.push_back(cv);
		}

		if (i < size && bytes[i] != 0)
			++i;
	}

	return final_result;
}


std::vector<std::vector<uint8_t>> generate_caves_hashes(std::vector<CodeCave> code_caves)
{
	std::vector<std::vector<uint8_t>> hashes;

	for (auto & v : code_caves)
	{
		std::vector<UINT8> bytes (v.size);
		read_buffer(v.addr, bytes.data(), v.size);
		auto hased = generate_SHA256(bytes);
		hashes.push_back(hased);
	}
	return hashes;
}

bool compare_hashes(std::vector<std::vector<UINT8>> original_hashes, std::vector<std::vector<UINT8>> new_hashes)
{
	auto size = min(original_hashes.size(), new_hashes.size());
	if (original_hashes.size() == new_hashes.size()) //Making sure we have the same ammount of hashes before comparing it to prevent an exception
	{
		for (int i = 0; i < size; i++)
		{
			if (original_hashes.at(i) != new_hashes.at(i))
			{
				printf("A Modified code cave was found\n");
				return true;
			}
		}
	}
	return false;
}


int main()
{
	if (!inicialite()) return 0;
	printf("[+] Process id: %d\n[+] Module base: %llu\n[+] Module size: %llu\n", processId, moduleBase, module_size);

	std::vector<uint8_t> data(module_size);

	if (!read_buffer(moduleBase, data.data(), module_size))
	{
		printf("Reading module data failed\n");
		return 0;
	}

	auto nt_headers = get_headers(data.data());
	auto target_section = get_section_by_name(nt_headers, ".text");

	auto original_caves = find_codecave(data.data(), module_size);
	auto original_code_cave_hashes = generate_caves_hashes(original_caves);

	printf("[+] Found %zu code caves initially\n", original_caves.size());
	printf("[+] Found .text section, VA: %llu, size: %llu\n",
		target_section->VirtualAddress, target_section->SizeOfRawData);

	std::vector<uint8_t> section_memory_chunk(target_section->SizeOfRawData);
	memcpy(section_memory_chunk.data(),
		reinterpret_cast<void*>(data.data() + target_section->VirtualAddress),
		target_section->SizeOfRawData);

	auto original_hash = generate_SHA256(section_memory_chunk);

	while (true)
	{
		Sleep(1000);

		if (!read_buffer(moduleBase, data.data(), module_size))
		{
			printf("[-] Failed to read module in loop\n");
			continue;
		}

		nt_headers = get_headers(data.data());
		target_section = get_section_by_name(nt_headers, ".text");

		std::vector<uint8_t> new_section_memory_chunk(target_section->SizeOfRawData);
		memcpy(new_section_memory_chunk.data(),
			reinterpret_cast<void*>(data.data() + target_section->VirtualAddress),
			target_section->SizeOfRawData);

		auto new_hash = generate_SHA256(new_section_memory_chunk);
		if (original_hash != new_hash)
		{
			printf("[!] Different hash detected! Modification in the .text section occurred\n");
		}

		auto new_caves = find_codecave(data.data(), module_size);

		auto new_code_cave_hashes = generate_caves_hashes(new_caves);
		if (compare_hashes(original_code_cave_hashes, new_code_cave_hashes))
		{
			printf("[!] Code cave content was modified — possible shellcode injection!\n");
		}
	}
}