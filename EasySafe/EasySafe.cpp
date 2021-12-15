#include "EasySafe.hpp"

namespace II {
	__int64 g_currentInstance;

	__int64 GetCurrentInstance() noexcept {
		return g_currentInstance;
	}

	uintptr_t SysHook(uintptr_t R10, uintptr_t RAX /*...*/) {
		{
			II::EasySafe* currentInstance = (II::EasySafe*)II::GetCurrentInstance();
			// This flag is there for prevent recursion
			if (!currentInstance->m_i_cb_flag) {
				currentInstance->m_i_cb_flag = true;

				uint8_t buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = { 0 };
				const auto symbol_info = (PSYMBOL_INFO)buffer;
				symbol_info->SizeOfStruct = sizeof(SYMBOL_INFO);
				symbol_info->MaxNameLen = MAX_SYM_NAME;
				uintptr_t displacement;

				// An invalid system service was specified in a system service call.
				if (RAX == 0xc000001c) return RAX;

				BOOL result = SymFromAddr(GetCurrentProcess(), R10, &displacement, symbol_info);


				// Deny access if function is hooked
				if (result && std::find(currentInstance->m_hookedSyscalls.begin(), currentInstance->m_hookedSyscalls.end(), symbol_info->Address) != std::end(currentInstance->m_hookedSyscalls)) {
					II::EasySafe::RegisterPayload loaded = (II::EasySafe::RegisterPayload)currentInstance->RunSysHook(symbol_info, R10, RAX);
					if (loaded.use) {
						RAX = loaded._RAX;
						R10 = loaded._R10;
					}
				}

				currentInstance->m_i_cb_flag = false;
				return RAX;
			}

			return RAX;
		}
	}

	NTSTATUS __stdcall LdrLoadDll_Detour(PWSTR SearchPath OPTIONAL, PULONG DllCharacteristics OPTIONAL, PUNICODE_STRING DllName, PVOID* BaseAddress)
	{
		II::EasySafe* currentInstance = (II::EasySafe*)II::GetCurrentInstance();

		BOOL bAllow = FALSE;
		CHAR cDllName[MAX_PATH];

		sprintf(cDllName, "%S", DllName->Buffer);

		for (auto& dll : currentInstance->m_dwAllowDll) // access by reference to avoid copying
		{
			if (strcmp(cDllName, dll.c_str()) == 0) {
				bAllow = TRUE;
				currentInstance->AddLog(1, "Allowing DLL: %s", cDllName);
				return LdrLoadDll_ptr(SearchPath, DllCharacteristics, DllName, BaseAddress);
			}
		}

		if (!bAllow)
		{
			currentInstance->AddLog(2, "Blocked: %s", cDllName);
		}

		return TRUE;
	}

	LdrLoadDll_t LdrLoadDll_ptr = nullptr;
}