# EasySafe
Known ring3 memory protections that can be handled at a simple level.

### Example usage
Check Example.cpp

### Syscall hooking
1. Add a syscall hook
2. Specify the action to be taken when the syscall you hooked is called. You can spoof the R10 and RAX values. (RAX is the value returned.)
![Syscall hooking 1](https://github.com/illegal-instruction-co/EasySafe/blob/main/assets/syscall_hooking_1.png?raw=true)


![Syscall hooking 2](https://github.com/illegal-instruction-co/EasySafe/blob/main/assets/syscall_hooking_2.png?raw=true)
![Syscall hooking 3](https://github.com/illegal-instruction-co/EasySafe/blob/main/assets/syscall_hooking_3.png?raw=true)
