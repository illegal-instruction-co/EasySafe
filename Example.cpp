#define NOMINMAX

#include <iostream>
#include <EasySafe.hpp>

int main() {

	/*
	* Setup EasySafe
	* --------------
	* First parameter is the payload
	* --------------
	* struct Payload {
	*   bool logs = true;
	*	bool tests = false;
	*	bool syscall_hooking = false;
	*	bool loadlibrary_hook = false;
	*	std::vector<std::string> dwAllowDll;
	* };
	*/
	std::vector<std::string> DllWhitelist = {
		"C:\\system32\\user32.dll",
		"kernel32.dll",
		"C:\\WINDOWS\\System32\\dbghelp.dll",
		"C:\\WINDOWS\\System32\\symsrv.dll"
	};

	auto instance = (new II::EasySafe({ true,
		true,
		true,
		true, DllWhitelist }));

	/*
	* Have a fantasy to do before the
	* protection instance is started?
	*/
	instance->beforeStart([&]() {
		instance->AddLog(1, "%s", "Attempting to start EasySafe instance...");
	});

	/*
	* Implement a syshook
	* In case of a possible call, 
	* we will call the given callback.
	*/
	instance->AddSysHook((__int64)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryVirtualMemory"));

	/*
	* Setup our sys callback
	*/
	instance->onSysHook([&](PSYMBOL_INFO symbol_info, uintptr_t R10, uintptr_t RAX) {
	// Print what we know
		instance->AddLog(1, "function: %s\n\treturn value: 0x%llx\n\treturn address: 0x%llx\n", symbol_info->Name, RAX, R10);
		II::EasySafe::RegisterPayload spoof({
			true,
			R10,			// Original R10
			0xDEADBEEF		// spoofed RAX
		});
		return spoof;
	});

	/*
	* Have a fantasy to do after the 
	* protection instance is started?
	*/
	instance->afterStart([&]() {
		instance->AddLog(1, "%s", "EasySafe instance started successfully!");
	});

	/*
	* Run EasySafe
	*/
	result_t hr = instance->Init();
	std::cout << II_SUCCEEDED(hr) << std::endl;

	std::cin.clear();
	std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
	std::cin.get();
}