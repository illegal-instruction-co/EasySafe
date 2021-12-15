#pragma once 
#include <EasySafe.h>

namespace II {
	extern __int64 g_currentInstance;
	extern __int64 GetCurrentInstance() noexcept;
}

namespace II {

	class EasySafe {
	public:
		/*
		* Payloads
		*/
		struct Payload {
			bool tests = false;
			bool syscall_hooking = false;
		};

		struct RegisterPayload {
			bool use = false;
			uintptr_t _R10 = 0x0;
			uintptr_t _RAX = 0X0;
		};

		PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION i_cb = { 0 };
		bool m_i_cb_flag = false;
		std::vector<uintptr_t> m_hookedSyscalls = {};

	private:
		Tests* g_tests;
		Payload g_config;
		std::function<void()> m_onStartCallback;
		std::function<void()> m_onBeforeStartCallback;
		std::function<II::EasySafe::RegisterPayload (PSYMBOL_INFO symbol_info, uintptr_t R10, uintptr_t RAX)> m_onSysHookCallback;

	public:

		EasySafe(Payload config) noexcept {
			g_config = config;
			II::g_currentInstance = (__int64)this;
		}

		inline void AddSysHook(uintptr_t addr) noexcept {
			return m_hookedSyscalls.push_back(addr);
		}

		inline void SafeSyscall(std::function<void()> callback) {

			// Check if unaffected functions don't crash
			NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0, nullptr, 0, nullptr);
			i_cb.Callback = nullptr;

			// Remove callback
			NtSetInformationProcess(GetCurrentProcess(), (PROCESS_INFORMATION_CLASS)0x28, &i_cb, sizeof(i_cb));

			callback();

			// Set our asm callback handler
			i_cb.Callback = middleware;

			// Setup the hook
			NtSetInformationProcess(GetCurrentProcess(), (PROCESS_INFORMATION_CLASS)0x28, &i_cb, sizeof(i_cb));
		}

		inline void onSysHook(std::function<II::EasySafe::RegisterPayload (PSYMBOL_INFO symbol_info, uintptr_t R10, uintptr_t RAX)> callback) {
			m_onSysHookCallback = callback;
		}

		inline II::EasySafe::RegisterPayload RunSysHook(PSYMBOL_INFO symbol_info, uintptr_t R10, uintptr_t RAX) {
			return m_onSysHookCallback(symbol_info, R10, RAX);
		}

		inline void afterStart(std::function<void()> callback) noexcept {
			m_onStartCallback = callback;
		}

		inline void beforeStart(std::function<void()> callback) noexcept {
			m_onBeforeStartCallback = callback;
		}

		inline bool Init() noexcept {

			// Call on before start callback
			m_onBeforeStartCallback();

			/*
			* Setup inline syscalls
			*/
			jm::init_syscalls_list();

			if (g_config.tests) {
				__int64 status = g_tests->Inline_Syscalls();
				if (status == 0) {
					std::cout << "Inline syscalls test pass!" << std::endl;
				}
				else {
					std::cout << "Inline syscalls status: " << status << std::endl;
					return false;
				};
			}

			/*
			* Setup instrumentation callbacks
			*/

			SymSetOptions(SYMOPT_UNDNAME);
			SymInitialize(GetCurrentProcess(), nullptr, TRUE);

			// Reserved is always 0
			i_cb.Reserved = 0;
			// x64 = 0, x86 = 1
			i_cb.Version = CALLBACK_VERSION;
			// Set our asm callback handler
			i_cb.Callback = middleware;

			// Setup the hook
			NtSetInformationProcess(GetCurrentProcess(), (PROCESS_INFORMATION_CLASS)0x28, &i_cb, sizeof(i_cb));
			
			if (g_config.tests) {
				// Run hooked function to test the hook
				MEMORY_BASIC_INFORMATION region = { nullptr };
				const auto status = NtQueryVirtualMemory(GetCurrentProcess(), GetModuleHandle(nullptr), MemoryBasicInformation, &region, sizeof(region), nullptr);
				// Print spoofed status
				std::cout << "\n[UNSAFE] NtQVM status: " << std::hex << status << std::endl;

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
					std::cout << "[ SAFE ] NtQVM status2: " << std::hex << status2 << std::endl;
				});
			}

			// Call on start callback
			m_onStartCallback();

			return true;
		}

	};
}
