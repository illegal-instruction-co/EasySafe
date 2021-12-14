#pragma once 

namespace II {
	class Tests {
	public:
		inline __int64 Inline_Syscalls() noexcept {
			NTSTATUS NtAllocateVirtualMemory(
				[in]      HANDLE    ProcessHandle,
				[in, out] PVOID * BaseAddress,
				[in]      ULONG_PTR ZeroBits,
				[in, out] PSIZE_T   RegionSize,
				[in]      ULONG     AllocationType,
				[in]      ULONG     Protect
			);

			void* allocation = nullptr;
			size_t size = 0x1000;
			NTSTATUS status = INLINE_SYSCALL(NtAllocateVirtualMemory)(GetCurrentProcess(), &allocation, 0, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
			return status;
		}
	};
}