# <img src="https://github.com/illegal-instruction-co/EasySafe/blob/main/assets/easysafe.png?raw=true" data-canonical-src="https://github.com/illegal-instruction-co/EasySafe/blob/main/assets/easysafe.png?raw=true" width="50" height="50" /> EasySafe
<br />
Known ring3 memory protections that can be handled at a simple level.

### Example usage
Check Example.cpp

### Syscall hooking
1. Add a syscall hook
2. Specify the action to be taken when the syscall you hooked is called. You can spoof the R10 and RAX values. (RAX is the value returned.)
3. If syscalls are not invoked safely in the process safe method, your callback will be executed.
4. The callback is called as it appears and the RAX is spoofed.

### LoadLibrary protection 

There are many ways to inject a dynamic link library using LoadLibrary in the process.
The main ones are:
1. Starting a new thread in the process using CreateRemoteThread and calling LoadLibrary inside the thread.
2. Using SetWindowsHookEx to hook the process window and call LoadLibrary without creating a new thread.

In either case, LoadLibrary will reference LdrLoadDll, which is still an internal function. In EasySafe, you can add certain dlls to the allowlist and call your callback without loading the rest.