#define _XOPEN_SOURCE
#include <signal.h>
#include <iostream>
#include <ucontext.h>
#include <mach-o/dyld_images.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <mach-o/loader.h>

#include <Zydis/Zydis.h>

#include <vector>
#include <map>

/// Get a list of executable memory regions in the current process.
/// \return A vector of pairs containing the address and size of executable regions.
std::vector<std::pair<uint64_t, uint64_t>> GetExecutableMemoryRegions()
{
    std::vector<std::pair<uint64_t, uint64_t>> executableRegions;
    task_t task;
    mach_vm_address_t currentAddress;
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t count;
    kern_return_t result;
    mach_vm_size_t size;
    uint32_t depth;

    currentAddress = 0;
    count = VM_REGION_SUBMAP_INFO_COUNT_64;
    result = KERN_SUCCESS;
    size = 0;
    depth = 1;

    //
    // Retrieve the task port for the current process.
    //
    task_for_pid(mach_task_self(), getpid(), &task);

    //
    // Enumerate pages until we hit an invalid address.
    //
    while (TRUE) {
        //
        // Recursively enumerate memory regions.
        //
        result = mach_vm_region_recurse(task, &currentAddress, &size, &depth, (vm_region_info_64_t)&info, &count);

        //
        // If we hit a invalid address, means no more memory to enumerate.
        //
        if (result == KERN_INVALID_ADDRESS)
        {
            break;
        }

        //
        // If we're in a submap, we should update our depth.
        //
        if (info.is_submap)
        {
            depth++;
            //printf ("\tFound submap region: %016llx-%016llx\n", currentAddress, currentAddress+size);
        }
        else
        {
            //printf ("Found region: %016llx-%016llx\n", currentAddress, currentAddress+size);

            //
            // Make sure to record the page if it is executable.
            //
            if(info.protection & VM_PROT_EXECUTE)
            {
               executableRegions.push_back(std::pair<uint64_t, uint64_t>(currentAddress, size));
            }

            //
            // Append the size of the current region to get the next memory page.
            //
            currentAddress += size;
        }
    }

    //
    // Make sure to free our task port.
    //
    if (task != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), task);
    }
    return executableRegions;
}

//
// Using global variables for cross-thread storage.
//
std::map<void*, std::vector<void*>> shellcodeFunctions;
std::map<u_long, std::pair<void*, u_long>> threadContext;

/// This is our SIGTRAP signal handler that is the core of the Exception Oriented Programming methodology.
/// \param signal The signal that we are handling.
/// \param si An informational structure about the signal.
/// \param context An informational structure about the context of when the signal occurred.
void signal_handler(int signal, siginfo_t *si, void *context)
{
    std::vector<void*> currentShellcodeFunction;
    uint64_t threadId;
    void* exceptionAddress;
    u_int64_t previousInt3Instruction;
    u_char previousInstructionByte;
    ucontext_t* signalContext;
    void* threadContextStartAddress;
    u_long threadContextStep;

    //
    // Retrieve exception details.
    //
    pthread_threadid_np(NULL, &threadId);  // Get the current thread's ID.
    signalContext = (ucontext_t*)context;
    exceptionAddress = si->si_addr;  // This is the "faulting address".
    previousInt3Instruction = (u_int64_t)exceptionAddress - 1;
    previousInstructionByte = *(u_char*)(previousInt3Instruction);  // Last byte should be an int3 instruction if first time calling.

    printf("Exception. Address = 0x%llx, Signal = %i, PrevByte = 0x%X, Code = %i\n", exceptionAddress, signal, previousInstructionByte, si->si_code);
    //
    // Check if the last instruction is int3.
    // This means that we are calling our shellcode function.
    //
    if(previousInstructionByte == 0xCC)
    {
        //
        // Find the shellcode for the given int3 instruction.
        //
        if(shellcodeFunctions.find((void*)previousInt3Instruction) == shellcodeFunctions.end())
        {
            printf("Could not find shellcode function for address 0x%llx.\n", previousInt3Instruction);
            return;
        }

        //
        // Grab the vector array of instruction pointers.
        //
        currentShellcodeFunction = shellcodeFunctions[(void*)previousInt3Instruction];
        threadContext[threadId] = std::pair<void*, u_long>((void*)previousInt3Instruction, 1);

        printf("\tRegistered thread 0x%X into call shellcode function state.\n", threadId);
        printf("\tEdited RIP from 0x%llx to 0x%llx.\n", signalContext->uc_mcontext->__ss.__rip, currentShellcodeFunction[0]);

        //
        // Edit the RIP to the first instruction for the shellcode function.
        //
        signalContext->uc_mcontext->__ss.__rip = (uint64_t)currentShellcodeFunction[0];

        //
        // Set the single step flag.
        //
        signalContext->uc_mcontext->__ss.__rflags |= 0x100;
    }
    //
    // If previous instruction is not int3, assume this is a single step.
    //
    else
    {
        //
        // Make sure this single step is for our registered thread.
        //
        if(threadContext.find(threadId) == threadContext.end())
        {
            printf("Could not find registered thread with ID 0x%X for address 0x%llx.\n", threadId, previousInt3Instruction);
            return;
        }

        //
        // Retrieve the thread context fields.
        //
        threadContextStartAddress = threadContext[threadId].first;
        threadContextStep = threadContext[threadId].second;

        currentShellcodeFunction = shellcodeFunctions[threadContextStartAddress];

        printf("\tSingle step.\n", threadId);
        printf("\tEdited RIP from 0x%llx to 0x%llx.\n", signalContext->uc_mcontext->__ss.__rip, currentShellcodeFunction[threadContextStep]);

        //
        // Edit the RIP to the next instruction for the shellcode function.
        //
        signalContext->uc_mcontext->__ss.__rip = (uint64_t)currentShellcodeFunction[threadContextStep];

        //
        // Set the single step flag.
        //
        signalContext->uc_mcontext->__ss.__rflags |= 0x100;

        //
        // Update the thread step.
        //
        threadContext[threadId].second++;
        threadContextStep = threadContext[threadId].second;

        //
        // If this is the last instruction for the shellcode,
        // remove the thread context and single step flag.
        //
        if(threadContextStep == currentShellcodeFunction.size())
        {
            printf("\tReached end of shellcode function 0x%llx, clearing context and trap flag.\n");
            signalContext->uc_mcontext->__ss.__rflags &= ~0x100;
            threadContext.erase(threadContext.find(threadId));
        }
    }
}

/// Find an assembly instruction in a legitimate executable region.
/// \param Instruction A pointer to the instruction assembled bytes.
/// \param InstructionSize The size of the Instruction array.
/// \return A pointer to a legitimate page containing the Instruction. NULL if not found.
void* FindInstruction(void* Instruction, size_t InstructionSize)
{
    auto executableRegions = GetExecutableMemoryRegions();
    uint64_t currentRegion;
    uint64_t currentRegionSize;
    u_int64_t currentOffset;

    //
    // Enumerate each executable region we found.
    //
    for(auto region : executableRegions)
    {
        currentRegion = region.first;
        currentRegionSize = region.second;

        //
        // Enumerate each byte in the current memory region.
        // We could enumerate by a step of InstructionSize,
        // but for our purposes, it does not matter if the
        // Instruction is unaligned.
        //
        for(int i = 0; i < currentRegionSize - InstructionSize; i++)
        {
            currentOffset = currentRegion + i;

            //
            // Check if the shellcode instruction matches.
            //
            if(memcmp((void*)currentOffset, Instruction, InstructionSize) == 0)
            {
                return (void*)currentOffset;
            }
        }
    }

    return NULL;
}

/// Create the context for executing a Shellcode function.
/// \param Shellcode A pointer to the shellcode to execute.
/// \param ShellcodeSize The size of the Shellcode array.
/// \return A pointer to an int3 instruction the caller must call to execute the Shellcode function. NULL if failure.
void* CreateShellcodeFunction(u_char* Shellcode, size_t ShellcodeSize)
{
    std::vector<void*> instructions;
    ZydisDecoder decoder;
    ZydisDecodedInstruction currentInstruction;
    ZyanUSize offset = 0;
    void* instructionLocation;
    void* functionLocation;

    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

    //
    // Enumerate each instruction in the Shellcode.
    //
    while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder,
                                                 Shellcode + offset,
                                                 ShellcodeSize - offset,
                                                 &currentInstruction)))
    {
        //
        // Find the instruction in a legitimate executable page.
        //
        instructionLocation = FindInstruction(Shellcode + offset, currentInstruction.length);
        if (instructionLocation == NULL)
        {
            printf("Could not find instruction at offset 0x%X.\n", offset);
            return NULL;
        }

        //
        // Add the location of the instruction for our signal handler.
        //
        instructions.push_back(instructionLocation);

        //
        // Update our offset for the next instruction.
        //
        offset += currentInstruction.length;

        printf("INSTRUCTION LOCATION 0x%llx, OFFSET 0x%X, SIZE 0x%X\n", instructionLocation, offset, currentInstruction.length);
    }

    //
    // Find any int3 instruction that we don't already have registered.
    //
    while ((functionLocation = FindInstruction((u_char*)"\xCC", 1)) && shellcodeFunctions.find(functionLocation) != shellcodeFunctions.end())
    {
    }

    printf("Function location = 0x%llx\n", functionLocation);

    //
    // Update the global variable context with the current Shellcode function.
    // This is used by the signal handler.
    //
    shellcodeFunctions[functionLocation] = instructions;

    return functionLocation;
}

int main()
{
    struct sigaction sa = {0};

    //
    // Prepare the sigaction structure.
    //
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = signal_handler;
    sa.sa_flags = SA_SIGINFO;

    //
    // Shellcode to execute.
    //
    u_char shellcode[] = {
            0xb8, 0x02, 0x00, 0x00, 0x00,     // mov eax, 2
            0x83, 0xc0, 0x05,                 // add eax, 5
            0xc3                              // ret
    };

    //
    // Install the global excetion handler.
    //
    sigaction(SIGTRAP, &sa, NULL);

    //
    // Create a fake "function" to call.
    //
    typedef int(__fastcall* func_t)();
    func_t func = (func_t) CreateShellcodeFunction(shellcode, sizeof(shellcode));

    //
    // Call the shellcode function.
    //
    printf("Calling func 0x%X...\n", *(u_char*)func);
    int a = func();

    //
    // Output for the shellcode should be 7.
    //
    printf("func result (7 is expected) = %i\n", a);

    return 0;
}