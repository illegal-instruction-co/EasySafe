#pragma once
#include <EasySafe.h>

namespace II {
	class EasySafe {
	public:
		/*
		* Payload
		*/
		struct Payload {
			bool tests = false;
		};
	private: 
		Tests* g_tests;
		Payload g_config;
	public:

		EasySafe(Payload config) {
			g_config = config;
		}

		inline bool Init() noexcept {

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

			return true;
		}
	};

}