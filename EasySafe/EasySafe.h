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

/*
* Config
*/
#include <config.h>

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

#include <utility/instrumentation_callbacks/minwin.hpp>

/*
* Tests
*/
#include <tests.hpp>