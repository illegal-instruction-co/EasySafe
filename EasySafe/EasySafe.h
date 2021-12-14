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
* Tests
*/
#include <tests.hpp>