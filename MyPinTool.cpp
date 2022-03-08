#include "pin.H"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <list>

using std::string;
using std::endl;
using std::cerr;
using std::vector;
using std::list;

vector<string> f_source;
//vector<string> f_sp;
vector<string> f_leak;

std::list<UINT32> addressTainted;
std::list<REG> regsTainted;

void init() {
	string fsource[] = { "ReadFile"/*,"ReadFileA","ReadFileW"*/ ,"_read" };
	//string fsp[] = { };
	string fleak[] = { "WriteFile"/*,"WriteFileA","WriteFileW"*/ ,"_write","CreateFile","CreateFileA","CreateFileW" };
	f_source =
		vector<string>(fsource, fsource + sizeof(fsource) / sizeof(fsource[0]));
	//f_sp = vector<string>(fsp, fsp + sizeof(fsp) / sizeof(fsp[0]));
	f_leak = vector<string>(fleak, fleak + sizeof(fleak) / sizeof(fleak[0]));
}

bool checkAlreadyRegTainted(REG reg) {
	std::list<REG>::iterator i;
	//LOG("CheckREG!!!\n");
	for (i = regsTainted.begin(); i != regsTainted.end(); i++) {
		if (*i == reg) {
			return true;
		}
	}
	return false;
}

VOID removeMemTainted(UINT32 addr) {
	addressTainted.remove(addr);
	LOG("\t" + hexstr(addr) + " is now freed\n");
}

VOID addMemTainted(UINT32 addr) {
	addressTainted.push_back(addr);
	LOG("\t" + hexstr(addr) + " is now tainted\n");
}

bool taintReg(REG reg) {
	//LOG("TaintREG!!!!\n");
	if (checkAlreadyRegTainted(reg) == true) {
		LOG("\t" + REG_StringShort(reg) + " is already tainted\n");
		return false;
	}

	switch (reg) {

		/*case REG_RAX:
			regsTainted.push_front(REG_RAX);*/
	case REG_EAX:
		regsTainted.push_front(REG_EAX);
	case REG_AX:
		regsTainted.push_front(REG_AX);
	case REG_AH:
		regsTainted.push_front(REG_AH);
	case REG_AL:
		regsTainted.push_front(REG_AL);
		break;

		/*case REG_RBX:
			regsTainted.push_front(REG_RBX);*/
	case REG_EBX:
		regsTainted.push_front(REG_EBX);
	case REG_BX:
		regsTainted.push_front(REG_BX);
	case REG_BH:
		regsTainted.push_front(REG_BH);
	case REG_BL:
		regsTainted.push_front(REG_BL);
		break;

		/*case REG_RCX:
			regsTainted.push_front(REG_RCX);*/
	case REG_ECX:
		regsTainted.push_front(REG_ECX);
	case REG_CX:
		regsTainted.push_front(REG_CX);
	case REG_CH:
		regsTainted.push_front(REG_CH);
	case REG_CL:
		regsTainted.push_front(REG_CL);
		break;

		/*case REG_RDX:
			regsTainted.push_front(REG_RDX);*/
	case REG_EDX:
		regsTainted.push_front(REG_EDX);
	case REG_DX:
		regsTainted.push_front(REG_DX);
	case REG_DH:
		regsTainted.push_front(REG_DH);
	case REG_DL:
		regsTainted.push_front(REG_DL);
		break;

		/*case REG_RDI:
			regsTainted.push_front(REG_RDI);*/
	case REG_EDI:
		regsTainted.push_front(REG_EDI);
	case REG_DI:
		regsTainted.push_front(REG_DI);
		/*case REG_DIL:
			regsTainted.push_front(REG_DIL);*/
		break;

		/*case REG_RSI:
			regsTainted.push_front(REG_RSI);*/
	case REG_ESI:
		regsTainted.push_front(REG_ESI);
	case REG_SI:
		regsTainted.push_front(REG_SI);
		/*case REG_SIL:
			regsTainted.push_front(REG_SIL);*/
		break;

	default:
		LOG("\t" + REG_StringShort(reg) + " can't be tainted\n");
		return false;
	}
	LOG("\t" + REG_StringShort(reg) + " is now tainted\n");
	return true;
}

bool removeRegTainted(REG reg) {
	switch (reg) {

		/*case REG_RAX:
			regsTainted.remove(REG_RAX);*/
	case REG_EAX:
		regsTainted.remove(REG_EAX);
	case REG_AX:
		regsTainted.remove(REG_AX);
	case REG_AH:
		regsTainted.remove(REG_AH);
	case REG_AL:
		regsTainted.remove(REG_AL);
		break;

		/*case REG_RBX:
			regsTainted.remove(REG_RBX);*/
	case REG_EBX:
		regsTainted.remove(REG_EBX);
	case REG_BX:
		regsTainted.remove(REG_BX);
	case REG_BH:
		regsTainted.remove(REG_BH);
	case REG_BL:
		regsTainted.remove(REG_BL);
		break;

		/*case REG_RCX:
			regsTainted.remove(REG_RCX);*/
	case REG_ECX:
		regsTainted.remove(REG_ECX);
	case REG_CX:
		regsTainted.remove(REG_CX);
	case REG_CH:
		regsTainted.remove(REG_CH);
	case REG_CL:
		regsTainted.remove(REG_CL);
		break;

		/*case REG_RDX:
			regsTainted.remove(REG_RDX);*/
	case REG_EDX:
		regsTainted.remove(REG_EDX);
	case REG_DX:
		regsTainted.remove(REG_DX);
	case REG_DH:
		regsTainted.remove(REG_DH);
	case REG_DL:
		regsTainted.remove(REG_DL);
		break;

		/*case REG_RDI:
			regsTainted.remove(REG_RDI);*/
	case REG_EDI:
		regsTainted.remove(REG_EDI);
	case REG_DI:
		regsTainted.remove(REG_DI);
		/*case REG_DIL:
			regsTainted.remove(REG_DIL);*/
		break;

		/*case REG_RSI:
			regsTainted.remove(REG_RSI);*/
	case REG_ESI:
		regsTainted.remove(REG_ESI);
	case REG_SI:
		regsTainted.remove(REG_SI);
		/*	case REG_SIL:
				regsTainted.remove(REG_SIL);*/
		break;

	default:
		return false;
	}
	LOG("\t" + REG_StringShort(reg) + " is now freed\n");
	return true;
}

VOID ReadMem(UINT32 insAddr/*, std::string insDis, UINT32 OperandCount*/, REG reg_r,
	UINT32 memOp) {
	std::list<UINT32>::iterator i;
	UINT32 addr = memOp;

	/*if (OperandCount != 2)
		return;*/
		//LOG("Len : " + hexstr(addressTainted.size()) + "\n");
	for (i = addressTainted.begin(); i != addressTainted.end(); i++) {
		if (addr == *i) {
			LOG("[READ in " + hexstr(addr) + "]\t insAddr: " + hexstr(insAddr) + "\n");
			taintReg(reg_r);
			return;
		}
	}
	/* if mem != tained and reg == taint => free the reg */
	if (checkAlreadyRegTainted(reg_r)) {
		LOG("[READ in " + hexstr(addr) + "]\t insAddr: " + hexstr(insAddr) + "\n");
		removeRegTainted(reg_r);
	}
	//LOG("HELLO");
}

VOID WriteMem(UINT32 insAddr,/* std::string insDis,UINT32 OperandCount, */ REG reg_r,
	UINT32 memOp) {
	std::list<UINT32>::iterator i;
	UINT32 addr = memOp;

	/*if (OperandCount != 2)
		return;*/

	for (i = addressTainted.begin(); i != addressTainted.end(); i++) {
		if (addr == *i) {
			LOG("[WRITE in " + hexstr(addr) + "]\t insAddr: " + hexstr(insAddr) + "\n");
			if (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))
				removeMemTainted(addr);
			return;
		}
	}
	if (checkAlreadyRegTainted(reg_r)) {
		LOG("[WRITE in " + hexstr(addr) + "]\t insAddr: " + hexstr(insAddr) + "\n");
		addMemTainted(addr);
	}
}

VOID spreadRegTaint(UINT32 insAddr, /*std::string insDis, UINT32 opCount,*/
	REG reg_r, REG reg_w) {
	/*if (opCount != 2)
		return;*/

	if (REG_valid(reg_w)) {
		//LOG("HERE!!!");
		if (checkAlreadyRegTainted(reg_w) &&
			(!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))) {
			LOG("[SPREAD]\t" + hexstr(insAddr) + "\n");
			LOG("\toutput: " + REG_StringShort(reg_w) + " | input: " + (REG_valid(reg_r) ? REG_StringShort(reg_r) : "constant") + "\n");
			removeRegTainted(reg_w);
		}
		else if (!checkAlreadyRegTainted(reg_w) &&
			checkAlreadyRegTainted(reg_r)) {
			LOG("[SPREAD]\t" + hexstr(insAddr) + "\n");
			LOG("\toutput: " + REG_StringShort(reg_w) + " | input: " + REG_StringShort(reg_r) + "\n");
			taintReg(reg_w);
		}
	}
}

VOID spreadBinaryRegTaint(UINT32 insAddr, /*std::string insDis, UINT32 opCount,*/
	REG reg_r, REG reg_w) {
	/*if (opCount != 2)
		return;*/

	if (REG_valid(reg_w)) {
		//LOG("HERE!!!");
		/*if (checkAlreadyRegTainted(reg_w) &&
			(!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))) {
			LOG("[SPREAD]\t" + hexstr(insAddr) + "\n");
			LOG("\toutput: " + REG_StringShort(reg_w) + " | input: " + (REG_valid(reg_r) ? REG_StringShort(reg_r) : "constant") + "\n");
			removeRegTainted(reg_w);
		}
		else */if (!checkAlreadyRegTainted(reg_w) &&
			checkAlreadyRegTainted(reg_r)) {
			LOG("[SPREAD]\t" + hexstr(insAddr) + "\n");
			LOG("\toutput: " + REG_StringShort(reg_w) + " | input: " + REG_StringShort(reg_r) + "\n");
			taintReg(reg_w);
		}
	}
}

INT32 icount = 0;

VOID docount() { icount++; }
// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID* v)
{
	// Insert a call to docount before every instruction, no arguments are passed
	//INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END);

	//if (INS_OperandCount(ins) > 1 && INS_IsMemoryRead(ins) &&
	//	INS_OperandIsMemory(ins, 1) && INS_OperandIsReg(ins, 0)) {
	//	LOG("Read " + string(INS_Disassemble(ins)) + "   " + hexstr(INS_OperandCount(ins)) + "\n");
	//	INS_InsertCall(
	//		ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
	//		IARG_ADDRINT, INS_Address(ins),
	//		//IARG_PTR, new string(INS_Disassemble(ins)),
	//		IARG_UINT32, INS_OperandCount(ins),
	//		IARG_UINT32, INS_OperandReg(ins, 0),
	//		IARG_MEMORYOP_EA, 0,
	//		IARG_END);
	//}
	if (INS_OperandCount(ins) > 1) {
		LOG("CATEGORY " + CATEGORY_StringShort(INS_Category(ins)) + " INS: " + INS_Disassemble(ins) + " Count: " + hexstr(INS_OperandCount(ins)) + "\n");
		for (UINT32 i = 0; i < INS_OperandCount(ins); i++)
		{
			LOG(hexstr(i) + " : ");
			if (INS_OperandIsMemory(ins, i))
			{
				LOG("Memory");
			}
			else if (INS_OperandIsReg(ins, i))
			{
				REG opReg = INS_OperandReg(ins, i);
				LOG(REG_StringShort(opReg));
			}
			else if (INS_OperandIsImmediate(ins, i))
			{
				// Get the value itself
				ADDRINT value = INS_OperandImmediate(ins, i);
				long signed_value = (long)value;
				LOG(hexstr(value));
			}
			LOG("\n");
		}
	}

	if (INS_OperandCount(ins) > 1 && INS_IsMemoryRead(ins)) {
		if (INS_OperandIsMemory(ins, 1) && INS_OperandIsReg(ins, 0)) {
			//LOG("Read " + string(INS_Disassemble(ins)) + "   " + hexstr(INS_OperandCount(ins)) + "\n");
			INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
				IARG_ADDRINT, INS_Address(ins),
				//IARG_PTR, new string(INS_Disassemble(ins)),
				//IARG_UINT32, INS_OperandCount(ins),
				IARG_UINT32, INS_OperandReg(ins, 0),
				IARG_MEMORYOP_EA, 0,
				IARG_END);
		}
		else if (INS_Category(ins) == XED_CATEGORY_POP)
		{
			INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
				IARG_ADDRINT, INS_Address(ins),
				//IARG_PTR, new string(INS_Disassemble(ins)),
				//IARG_UINT32, INS_OperandCount(ins),
				IARG_UINT32, INS_RegR(ins, 0),
				IARG_MEMORYOP_EA, 0,
				IARG_END);
		}
	}
	else if (INS_OperandCount(ins) > 1 && INS_IsMemoryWrite(ins)) {
		//LOG("Write " + string(INS_Disassemble(ins)) + "   " + hexstr(INS_OperandCount(ins)) + "\n");
		if (INS_Category(ins) == XED_CATEGORY_PUSH)
		{
			INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
				IARG_ADDRINT, INS_Address(ins),
				//IARG_PTR, new string(INS_Disassemble(ins)),
				//IARG_UINT32, INS_OperandCount(ins),
				IARG_UINT32, INS_OperandReg(ins, 0),
				IARG_MEMORYOP_EA, 0,
				IARG_END);
		}
		else {
			INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
				IARG_ADDRINT, INS_Address(ins),
				//IARG_PTR, new string(INS_Disassemble(ins)),
				//IARG_UINT32, INS_OperandCount(ins),
				IARG_UINT32, INS_RegW(ins, 0),
				IARG_MEMORYOP_EA, 0,
				IARG_END);
		}
	}
	else if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0)) {
		//LOG("Spread " + string(INS_Disassemble(ins)) + "   " + hexstr(INS_OperandCount(ins)) + "\n");
		if (INS_Category(ins) == XED_CATEGORY_BINARY)
		{
			INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)spreadBinaryRegTaint,
				IARG_ADDRINT, INS_Address(ins),
				//IARG_PTR, new string(INS_Disassemble(ins)),
				//IARG_UINT32, INS_OperandCount(ins),
				IARG_UINT32, INS_RegR(ins, 0),
				IARG_UINT32, INS_RegW(ins, 1),
				IARG_END);
		}
		else {
			INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)spreadRegTaint,
				IARG_ADDRINT, INS_Address(ins),
				//IARG_PTR, new string(INS_Disassemble(ins)),
				//IARG_UINT32, INS_OperandCount(ins),
				IARG_UINT32, INS_RegR(ins, 0),
				IARG_UINT32, INS_RegW(ins, 0),
				IARG_END);
		}
	}
}

// This function is called before every instruction is executed
//VOID getParam(std::vector<string>::iterator name, UINT32* ps0, UINT32 ps1) {
//	std::cout << *name << ": param1 => " << ps0 << " , param2 => " << ps1
//		<< std::endl;
//}

VOID* tmpLpBuffer;
VOID* tmpLpNumberOfBytes;
VOID getReadAndWrite(std::vector<string>::iterator name, ADDRINT hFile, VOID* lpBuffer, int32_t nNumberOfBytes, VOID* lpNumberOfBytes, VOID* lpOverlapped)
{
	// Print the input argument of each function
	/*
	BOOL WriteFile(
		HANDLE       hFile,
		LPCVOID      lpBuffer,
		DWORD        nNumberOfBytesToWrite,
		LPDWORD      lpNumberOfBytesWritten,
		LPOVERLAPPED lpOverlapped
	);
	*/
	std::cout << std::hex << *name << "( 0x" << hFile << ", 0x" << (ADDRINT)lpBuffer << ", 0x" << nNumberOfBytes << ", 0x" << (ADDRINT)lpNumberOfBytes << ", 0x" << (ADDRINT)lpOverlapped << ")" << endl;
	if (*name == "WriteFile")
	{
		std::cout << "  Write content: " << (char*)lpBuffer << endl;
		//std::cout << addressTainted.size() << std::endl;
		for (std::list<UINT32>::iterator it = addressTainted.begin(); it != addressTainted.end(); it++) {
			//std::cout << "=====================   " + hexstr(*it) + "=========================\n" << std::endl;
			if ((UINT32)lpBuffer <= *it && (UINT32)(lpBuffer)+nNumberOfBytes > *it) {
				std::cout << "\x1b[31mLeaked information from address " << *it
					<< "\x1b[0m" << std::endl;
			}
		}
	}
	else if (*name == "ReadFile") {
		tmpLpBuffer = lpBuffer;
		tmpLpNumberOfBytes = lpNumberOfBytes;
	}

}

VOID getReadRet() {
	if (tmpLpNumberOfBytes && tmpLpBuffer)
	{
		for (size_t i = 0; i < *(UINT32*)tmpLpNumberOfBytes; i++)
			addMemTainted((UINT32)tmpLpBuffer + i);
		std::cout << "\x1b[34m[TAINT]\tbytes tainted from " << std::hex << "0x"
			<< (UINT32)tmpLpBuffer << " to 0x" << (UINT32)tmpLpBuffer + *(UINT32*)tmpLpNumberOfBytes
			<< " (via ReadFile )\x1b[0m" << std::endl;
		tmpLpNumberOfBytes = NULL;
		tmpLpBuffer = NULL;
	}

}


VOID getWrite(std::vector<string>::iterator name, UINT32* ps0, UINT32 ps1) {
	std::cout << *name << ": param1 => " << ps0 << " , param2 => " << ps1
		<< std::endl;
	for (std::list<UINT32>::iterator it = addressTainted.begin();
		it != addressTainted.end(); it++) {
		if ((UINT32)ps0 <= *it && (UINT32)(ps0)+ps1 > *it) {
			std::cout << "\x1b[31mLeaked information from address " << *it
				<< "\x1b[0m" << std::endl;
		}
	}
}

UINT32 tmp_addr;
bool taint = false;
VOID getReadParam(std::vector<string>::iterator name, UINT32 ps0, UINT32* ps1) {
	std::cout << *name << ": param1 => " << ps0 << " , param2 => " << ps1
		<< std::endl;
	if (ps0 == 0) {
		tmp_addr = (UINT32)ps1;
		taint = true;
	}
}

VOID getReadRet(std::vector<string>::iterator name, UINT32 ret0) {
	std::cout << *name << ": ret => " << ret0 << std::endl;
	if (taint) {
		for (size_t i = 0; i < ret0; i++)
			addressTainted.push_back((UINT32)(tmp_addr + i));
		std::cout << "\x1b[34m[TAINT]\tbytes tainted from " << std::hex << "0x"
			<< (UINT32)tmp_addr << " to 0x" << (UINT32)(tmp_addr + ret0)
			<< " (via " << *name << ")\x1b[0m" << std::endl;
		taint = false;
	}
}


std::list<string> names;
VOID getName(CHAR* name) { printf("\x1b[31m%s\x1b[0m\n", name); }

bool in(string s, vector<string> array) {
	std::vector<string>::iterator pos = std::find(array.begin(), array.end(), s);
	if (pos == array.end())
		return false;
	else
		return true;
}

VOID Routine(RTN rtn, VOID* v) {
	// Allocate a counter for this routine
	string name = RTN_Name(rtn);
	//names.push_back(name);
	RTN_Open(rtn);

	// Insert a call at the entry point of a routine to increment the call count

	//if (in(name, f_sp)) {
	//	std::vector<string>::iterator pos =
	//		std::find(f_sp.begin(), f_sp.end(), name);

	//}
	//std::cout << name << std::endl;
	//RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)getWrite, IARG_ADDRINT, pos, IARG_END);

	if (in(name, f_leak)) {

		std::vector<string>::iterator pos =
			std::find(f_leak.begin(), f_leak.end(), name);
		//std::cout << name << std::endl;
		if (name == "_write") {
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)getWrite, IARG_ADDRINT, pos,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
		}
		else {
			RTN_InsertCall(
				rtn,
				IPOINT_BEFORE, (AFUNPTR)getReadAndWrite,
				IARG_ADDRINT, pos,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
				IARG_END);
		}
	}
	if (in(name, f_source)) {
		std::vector<string>::iterator pos =
			std::find(f_source.begin(), f_source.end(), name);
		//std::cout << name << std::endl;
		if (name == "_read")
		{
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)getReadParam, IARG_ADDRINT,
				pos, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getReadRet, IARG_ADDRINT, pos,
				IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
		}
		else {
			RTN_InsertCall(
				rtn,
				IPOINT_BEFORE, (AFUNPTR)getReadAndWrite,
				IARG_ADDRINT, pos,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
				IARG_END);
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getReadRet, IARG_END);
		}
	}

	RTN_Close(rtn);
}

// This function is called when the application exits
// It prints the name and count for each procedure
VOID Fini(INT32 code, VOID* v) {}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage() {
	cerr << "This Pintool counts the number of times a routine is executed"
		<< endl;
	cerr << "and the number of instructions executed in a routine" << endl;
	cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[]) {
	// Initialize symbol table code, needed for rtn instrumentation
	init();

	PIN_InitSymbols();

	// Initialize pin
	if (PIN_Init(argc, argv))
		return Usage();

	PIN_SetSyntaxIntel();

	RTN_AddInstrumentFunction(Routine, 0);
	INS_AddInstrumentFunction(Instruction, 0);
	PIN_AddFiniFunction(Fini, 0);
	PIN_StartProgram();

	return 0;
}