#pragma once 

#include <EasySafe/src/EasySafe.h>

namespace II {
	extern __int64 g_currentInstance;
	extern __int64 GetCurrentInstance() noexcept;
}

namespace II {

	class EasySafe {

	/*
	* Public Payloads
	*/
	public:
		struct Payload {
			bool logs = true;
			bool tests = false;
			bool not_allow_byte_patching = true;
			bool syscall_hooking = false;
			bool loadlibrary_hook = false;
			std::vector<std::string> dwAllowDll;
		};

		struct RegisterPayload {
			bool use = false;
			uintptr_t _R10 = 0x0;
			uintptr_t _RAX = 0X0;
		};

	/*
	* Public variables
	*/
	public: 
		PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION i_cb = { 0 };
		bool m_i_cb_flag = false;
		std::vector<uintptr_t> m_hookedSyscalls = {};
		std::vector<std::string> m_dwAllowDll;

	/*
	* Private variables
	*/
	private:
		Tests* g_tests;
		Payload g_config;
		std::function<void()> m_onStartCallback;
		std::function<void()> m_onBeforeStartCallback;
		std::function<II::EasySafe::RegisterPayload(PSYMBOL_INFO symbol_info, uintptr_t R10, uintptr_t RAX)> m_onSysHookCallback;
		std::function<void(const char* dllPath)> m_onLoadLibraryProtectionCallback;
		std::function<void(const char* dllPath)> m_onBytePatchingProtectionCallback;

		/*
		* TO DO 
		* Changable allowed shared paged modules ? 
		*/
		std::vector<std::string> m_sharedAllowedModules = {
							std::string(""),
							std::string("C:\\WINDOWS\\System32\\bcryptPrimitives.dll")
		};

	/*
	* Private functions
	*/
	private:
	    inline result_t LoadLibraryProtection() noexcept {

			result_t hr = II_S_OK;

			LdrLoadDll_t LdrLoadDll = (LdrLoadDll_t)GetProcAddress(LoadLibraryA("ntdll.dll"), "LdrLoadDll");

			if(MH_CreateHook(LdrLoadDll, &II::LdrLoadDll_Detour, (LPVOID*)&II::LdrLoadDll_ptr) != MH_OK) hr = II_E_INVALIDARG;
			if(MH_EnableHook(LdrLoadDll) != MH_OK) hr = II_E_INVALIDARG;

			return hr;
		}

		__forceinline result_t InlineSyscalls() noexcept {
			/*
			* Setup inline syscalls
			*/
			jm::init_syscalls_list();

			__int64 status = g_tests->Inline_Syscalls();
			if (status == 0) {
				this->AddLog(3, "Inline syscalls status: %b", status == 0x0);
			}
			else {
				this->AddLog(2, "Inline syscalls status: 0x%llx", status);
				return II_E_NOTIMPL;
			};
			return II_S_OK;
		}

		__forceinline result_t IC() noexcept {
			result_t hr = II_S_OK;
			SymSetOptions(SYMOPT_UNDNAME);
			SymInitialize(GetCurrentProcess(), nullptr, TRUE) == true ? hr = II_S_OK : hr = II_E_INVALIDARG;

			// Reserved is always 0
			i_cb.Reserved = 0;
			// x64 = 0, x86 = 1
			i_cb.Version = CALLBACK_VERSION;
			// Set our asm callback handler
			i_cb.Callback = middleware;

			// Setup the hook
			NtSetInformationProcess(GetCurrentProcess(), (PROCESS_INFORMATION_CLASS)0x28, &i_cb, sizeof(i_cb)) == 0x0 ? hr = II_S_OK : hr = II_E_INVALIDARG;

			if (g_config.tests) {
				// Run hooked function to test the hook
				MEMORY_BASIC_INFORMATION region = { nullptr };
				const auto status = NtQueryVirtualMemory(GetCurrentProcess(), GetModuleHandle(nullptr), MemoryBasicInformation, &region, sizeof(region), nullptr);
				// Print spoofed status
				this->AddLog(1, "[UNSAFE] NtQVM status:  0x%llx", status);

				// Crash inline syscalls ( will be crash about 0xC0000005 )
				// MEMORY_BASIC_INFORMATION region2 = { nullptr };
				// const auto InlineStatus = INLINE_SYSCALL(NtQueryVirtualMemory)(GetCurrentProcess(), GetModuleHandle(nullptr), MemoryBasicInformation, &region2, sizeof(region2), nullptr);
				// std::cout << "[+] NtQVM status: " << std::hex << InlineStatus << std::endl;

				// Safe syscalls 
				this->SafeSyscall([&]() {
					// Run hooked function to test the hook
					MEMORY_BASIC_INFORMATION region2 = { nullptr };
					const auto status2 = NtQueryVirtualMemory(GetCurrentProcess(), GetModuleHandle(nullptr), MemoryBasicInformation, &region2, sizeof(region2), nullptr);
					// Print spoofed status
					this->AddLog(1, "[ SAFE ] NtQVM status2: 0x%llx", status2);
					});
			}
			return hr;
		}

		__forceinline void AddLogC(int type, const char* string, fmt::printf_args formatList) {
			if (g_config.logs) {
				auto msg = fmt::vsprintf(string, formatList);
				switch (type)
				{
				case 1:
					std::cout << "[LOG] " << msg << std::endl;
					break;
				case 2:
					std::cerr << "[ERR] " << msg << std::endl;
					break;
				case 3: 
					std::cout << "[SUC] " << msg << std::endl;
					break;
				default:
					std::cout << msg << std::endl;
					break;
				}
			}
		}

		__forceinline result_t BytePatchingProtection() {
			result_t hr = II_S_OK;

			HMODULE hMods[1024];
			HANDLE hProcess = GetCurrentProcess();
			DWORD cbNeeded;
			unsigned int i;

			if (!hProcess) return II_E_NOTIMPL;

			if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
			{
				for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
				{
					TCHAR szModName[MAX_PATH];

					// Get the full path to the module's file.

					if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
						sizeof(szModName) / sizeof(TCHAR)))
					{
						/*
						* to do
						* new_scalar.cpp issue exits
						*/
						std::thread([&] {
							while (true) {
								static auto module = GetModuleHandle(szModName);
								static auto process = GetCurrentProcess();
								static MODULEINFO modInfo;
								static auto res = GetModuleInformation(process, module, &modInfo, sizeof(modInfo));
								for (size_t i = (__int64)modInfo.lpBaseOfDll; i < (__int64)modInfo.lpBaseOfDll + modInfo.SizeOfImage; i++)
								{
									this->SafeSyscall([&]() {
										MEMORY_BASIC_INFORMATION Mbi = { 0 };
										size_t len;
										auto result = NtQueryVirtualMemory(hProcess, (PVOID)i, MemoryBasicInformation, &Mbi, size_t(sizeof(MEMORY_BASIC_INFORMATION)), &len);
										for (int k = 0; k < len / sizeof(PMEMORY_BASIC_INFORMATION); k++) {
											void* manipuledAddress = ((PMEMORY_BASIC_INFORMATION)&Mbi)[k].BaseAddress;
											for (int i = 0; i < len / sizeof(PSAPI_WORKING_SET_EX_INFORMATION); i++) {
												if (((PPSAPI_WORKING_SET_EX_INFORMATION)&Mbi)[i].VirtualAttributes.Shared) {
													BOOL allowed = false;
													std::wstring moduleW(&szModName[0]); //convert to wstring
													std::string moduleStr(moduleW.begin(), moduleW.end());
													for (auto dll : m_sharedAllowedModules) if ((moduleStr == dll)) allowed = true;
													if (!allowed) {
														// Byte patched
														this->AddLog(1, "Byte patched on: %s", moduleStr);
														m_onBytePatchingProtectionCallback(moduleStr.c_str());
													}
												}
											}
											std::this_thread::sleep_for(std::chrono::milliseconds(250));
										}
									});
									std::this_thread::sleep_for(std::chrono::milliseconds(250));
								}
								std::this_thread::sleep_for(std::chrono::milliseconds(2500));
							}
						}).detach();
					}
				}
			}
			return hr;
		}

	/*
	* Public functions
	*/
	public:

		EasySafe(Payload config) noexcept {
			g_config = config;
			if (g_config.dwAllowDll.size() > 0) m_dwAllowDll = g_config.dwAllowDll;
			II::g_currentInstance = (__int64)this;
		}

		template<typename... TArgs>
		__forceinline void AddLog(int type, const char* string, const TArgs&... args) noexcept {
			AddLogC(type, string, fmt::make_printf_args(args...));
		}

		__forceinline void AddSysHook(uintptr_t addr) noexcept {
			return m_hookedSyscalls.push_back(addr);
		}

		__forceinline result_t SafeSyscall(std::function<void()> callback) noexcept {

			result_t hr = II_S_OK;

			// Check if unaffected functions don't crash
			NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0, nullptr, 0, nullptr) == 0x0 ? hr = II_S_OK : hr = II_E_INVALIDARG;
			i_cb.Callback = nullptr;

			// Remove callback
			NtSetInformationProcess(GetCurrentProcess(), (PROCESS_INFORMATION_CLASS)0x28, &i_cb, sizeof(i_cb)) == 0x0 ? hr = II_S_OK : hr = II_E_INVALIDARG;

			callback();

			// Set our asm callback handler
			i_cb.Callback = middleware;

			// Setup the hook
			NtSetInformationProcess(GetCurrentProcess(), (PROCESS_INFORMATION_CLASS)0x28, &i_cb, sizeof(i_cb)) == 0x0 ? hr = II_S_OK : hr = II_E_INVALIDARG;

			return hr;
		}

		__forceinline void onSysHook(std::function<II::EasySafe::RegisterPayload (PSYMBOL_INFO symbol_info, uintptr_t R10, uintptr_t RAX)> callback) {
			m_onSysHookCallback = callback;
		}

		__forceinline void onLoadLibraryInjection(std::function<void(const char* dllPath)> callback) {
			m_onLoadLibraryProtectionCallback = callback;
		}

		__forceinline void onBytePatching(std::function<void(const char* dllPath)> callback) {
			m_onBytePatchingProtectionCallback = callback;
		}

		__forceinline void RunLoadLibraryInjection(const char* dllPath) {
			return m_onLoadLibraryProtectionCallback(dllPath);
		}

		__forceinline II::EasySafe::RegisterPayload RunSysHook(PSYMBOL_INFO symbol_info, uintptr_t R10, uintptr_t RAX) {
			return m_onSysHookCallback(symbol_info, R10, RAX);
		}

		__forceinline void afterStart(std::function<void()> callback) noexcept {
			m_onStartCallback = callback;
		}

		__forceinline void beforeStart(std::function<void()> callback) noexcept {
			m_onBeforeStartCallback = callback;
		}

		__forceinline result_t Init() noexcept {

			result_t hr = II_S_OK;

			// Init minhook
			if (MH_Initialize() != MH_OK) {
				hr = II_E_INVALIDARG; 
				return hr;
			}

			// Call on before start callback
			m_onBeforeStartCallback();

			if (g_config.tests) if (hr = II_FAILED(InlineSyscalls())) return hr;

			/*
			* Setup loadlibrary protection
			*/
			if (g_config.loadlibrary_hook) if (hr = II_FAILED(LoadLibraryProtection())) return hr;

			/*
			* Setup instrumentation callbacks
			*/

			if (g_config.syscall_hooking) if (hr = II_FAILED(IC())) return hr;
	
			/*
			* Start byte patching protection
			*/
			if (g_config.not_allow_byte_patching) if(hr = II_FAILED(BytePatchingProtection())) return hr;

			// Call on start callback
			m_onStartCallback();

			return hr;
		}

	};
}
