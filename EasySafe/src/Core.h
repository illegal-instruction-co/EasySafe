#pragma once 
#include <iostream>

// Generic result type.
typedef uint32_t result_t;

// Common error code definitions
#define II_S_OK					0x0
#define II_E_NOTIMPL			0x80004001
#define II_E_NOINTERFACE		0x80004002
#define II_E_INVALIDARG			0x80070057

// Success/failure macros
#define II_SUCCEEDED(x)			(((x) & 0x80000000) == 0)
#define II_FAILED(x)			(!II_SUCCEEDED(x))