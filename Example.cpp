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
	*	bool tests = false;
	*	bool syscall_hooking = false;
	* };
	*/
	auto instance = (new II::EasySafe({ false, true }));

	/*
	* Have a fantasy to do before the
	* protection instance is started?
	*/
	instance->beforeStart([&]() {
		std::cout << "Attempting to start EasySafe instance..." << std::endl;
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
		std::cout << "function: " << symbol_info->Name << " return value: " << std::hex << RAX << " return address:" << R10;
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
		std::cout << "EasySafe instance started successfully!" << std::endl;
	});

	/*
	* Run EasySafe
	*/
	instance->Init();

	std::cin.clear();
	std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
	std::cin.get();
}