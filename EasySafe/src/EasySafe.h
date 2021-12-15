#pragma once

/*
* Copyright 2021 ILLEGAL-INSTRUCTION-CO
*
* I am too lazy to find a suitable license for this app.
* You can do whatever you want with this app and you don't have to mention my name.
* Life is really hard, and sometimes we need to make it easy for each other. Bye babe.
* -----------------
* MBK
* -----------------
*/

#include <windows.h>
#include <iostream>
#include <functional>
#include <thread>
#include <future>
#include <psapi.h>

/*
* Core
*/
#include <EasySafe/src/Core.h>
#include <EasySafe/src/config.h>

/*
* FMT 
*/
#include <fmt/printf.h>

/*
* Inline syscalls.
* -----------------
* https://j00ru.vexillium.org/syscalls/win32k/64/
* -----------------
* Avoiding instrumentation callbacks a.k.a. syscall callbacks.
* https://bestofcpp.com/repo/Deputation-instrumentation_callbacks-cpp-utilities
* -----------------
* Credits Justas Masiulis
*/

#include <utility/inline_syscall/in_memory_init.hpp>

/*
* Instrumentation callbacks 
* -----------------
* https://bestofcpp.com/repo/Deputation-instrumentation_callbacks-cpp-utilities
* -----------------
* Who are the naughty boys? Let's catch
* -----------------
* Credits wlan, Alex Ionescu 
*/

#include <utility/instrumentation_callbacks/middleware.hpp>

/*
* Byte patching hooks
* -----------------
* Minhook 
* -----------------
* To do ( I was lazy to code )
* -----------------
* Credits
* TsudaKageyu
*/
#include <utility\minhook\include\MinHook.h>
#if defined _M_X64
#pragma comment(lib, "libMinHook-x64-v141-mtd.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook-x86-v141-mtd.lib")
#endif

/*
* Tests
*/
#include <EasySafe/src/tests.hpp>

namespace II {
	typedef NTSTATUS (WINAPI* LdrLoadDll_t) (PWSTR SearchPath OPTIONAL,
		PULONG DllCharacteristics OPTIONAL,
		PUNICODE_STRING DllName,
		PVOID* BaseAddress);

	extern uintptr_t SysHook(uintptr_t R10, uintptr_t RAX /*...*/);
	extern NTSTATUS __stdcall LdrLoadDll_Detour(PWSTR SearchPath OPTIONAL, PULONG DllCharacteristics OPTIONAL, PUNICODE_STRING DllName, PVOID* BaseAddress);
	extern LdrLoadDll_t LdrLoadDll_ptr;
}