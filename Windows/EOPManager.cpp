/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2022
 */
#include "EOPManager.h"

//
// Resolve the ntdll function we need in EOPManager::FindInstruction.
//
RtlLookupFunctionEntry_t fRtlLookupFunctionEntry = RCAST<RtlLookupFunctionEntry_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlLookupFunctionEntry"));

//
// Our internal structures.
//
std::map<PVOID, std::vector<PVOID>> EOPManager::ShellcodeFunctions;
std::map<DWORD, std::pair<PVOID, ULONG>> EOPManager::ThreadContext;

/// <summary>
/// Find the next executable section in a given image.
/// </summary>
/// <param name="ImageBase">The base of the image to enumerate.</param>
/// <param name="ExecSectionBase">The address of the previously retrieved section. This can be NULL.</param>
/// <param name="ExecSectionSize">The size of the previously retrieved section. This can be 0.</param>
/// <returns>TRUE if successfully found next section, FALSE otherwise (i.e reached end of exec sections).</returns>
BOOL
EOPManager::FindNextExecSection (
	_In_ PVOID ImageBase,
	_Inout_ PVOID& ExecSectionBase,
	_Inout_ SIZE_T& ExecSectionSize
	)
{
	BOOL result;
	PIMAGE_DOS_HEADER imageDosHeader;
	PIMAGE_NT_HEADERS imageNtHeader;
	PIMAGE_SECTION_HEADER imageSectionHeader;
	BOOL foundStartSectionBase;
	ULONG i;
	PVOID currentSectionBase;
	BOOLEAN foundSection;

	result = FALSE;
	ExecSectionSize = 0;
	foundStartSectionBase = FALSE;
	foundSection = FALSE;

	//
	// Check if a starting section was specified. If not, return the first section.
	//
	if (ExecSectionBase == NULL)
	{
		foundStartSectionBase = TRUE;
	}

	imageDosHeader = RCAST<PIMAGE_DOS_HEADER>(ImageBase);
	if (imageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		DBGPRINT("EOPManager!FindNextExecSection: The image has an invalid DOS Header Magic value.");
		goto Exit;
	}

	imageNtHeader = RCAST<PIMAGE_NT_HEADERS>(RCAST<ULONG_PTR>(imageDosHeader) + imageDosHeader->e_lfanew);
	if (imageNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		DBGPRINT("EOPManager!FindNextExecSection: The image has an invalid NT Header Magic value.");
		goto Exit;
	}

	imageSectionHeader = IMAGE_FIRST_SECTION(imageNtHeader);

	//
	// Enumerate each section of the driver for the ".text" section.
	//
	for (i = 0; i < imageNtHeader->FileHeader.NumberOfSections; i++)
	{
		currentSectionBase = RCAST<PVOID>(RCAST<ULONG_PTR>(imageDosHeader) + imageSectionHeader[i].VirtualAddress);
		if (foundStartSectionBase == FALSE && currentSectionBase == ExecSectionBase)
		{
			foundStartSectionBase = TRUE;
			continue;
		}
		else if (foundStartSectionBase && FlagOn(imageSectionHeader[i].Characteristics, IMAGE_SCN_MEM_EXECUTE))
		{
			ExecSectionBase = currentSectionBase;
			ExecSectionSize = imageSectionHeader[i].SizeOfRawData;
			foundSection = TRUE;
			break;
		}
	}

	if (foundSection == FALSE)
	{
		ExecSectionBase = NULL;
		ExecSectionSize = 0;
	}
Exit:
	return foundSection;
}

/// <summary>
/// This exception handler contains the primary logic for Exception Oriented Programming.
/// See the article for more details on how this works. Too much to fit into a summary.
/// </summary>
/// <param name="ExceptionInfo">Information about the exception.</param>
/// <returns>EXCEPTION_CONTINUE_EXECUTION or EXCEPTION_CONTINUE_SEARCH</returns>
LONG
EOPManager::GenericExceptionHandler (
	_Inout_ PEXCEPTION_POINTERS ExceptionInfo
	)
{
	DWORD currentThreadID;
	std::vector<PVOID> currentFunction;
	ULONG exceptionCode;
	PVOID exceptionAddress;
	std::pair<PVOID, ULONG> threadContext;

	currentThreadID = GetCurrentThreadId();
	exceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
	exceptionAddress = ExceptionInfo->ExceptionRecord->ExceptionAddress;

	//
	// If we see an int3 exception, this is likely
	// the start of a shellcode function.
	//
	if (exceptionCode == STATUS_BREAKPOINT)
	{
		//
		// Make sure that the given int3 instruction has a
		// corresponding shellcode function.
		//
		if (EOPManager::ShellcodeFunctions.find(exceptionAddress) == EOPManager::ShellcodeFunctions.end())
		{
			DBGPRINT("Could not find the shellcode function for int3 instruction at 0x%llx.", exceptionAddress);
			goto Exit;
		}

		//
		// Retrieve the vector of instructions for the shellcode function.
		//
		currentFunction = EOPManager::ShellcodeFunctions[exceptionAddress];

		//
		// Create the context for this shellcode function.
		// The index is 1 because we are going to execute the
		// 0th instruction after this exception is handled.
		//
		EOPManager::ThreadContext[currentThreadID] = std::pair<PVOID, ULONG>(exceptionAddress, 1);

		DBGPRINT("Registered EOP thread with ID 0x%X", currentThreadID);

		//
		// Edit the RIP to point to the first instruction of the shellcode.
		// Add the single step flag to break after the first instruction is executed.
		//
		ExceptionInfo->ContextRecord->Rip = RCAST<DWORD64>(currentFunction[0]);
		ExceptionInfo->ContextRecord->EFlags |= 0x100;

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	//
	// If it's a single step exception, we are likely
	// in the middle of executing a shellcode function.
	//
	else if (exceptionCode == STATUS_SINGLE_STEP)
	{
		//
		// Check if the current thread is in the
		// middle of executing a shellcode function.
		//
		if (EOPManager::ThreadContext.find(currentThreadID) == EOPManager::ThreadContext.end())
		{
			DBGPRINT("Could not find the context for thread 0x%X.", currentThreadID);
			goto Exit;
		}

		//
		// Retrieve the vector of instructions for the shellcode function.
		//
		threadContext = EOPManager::ThreadContext[currentThreadID];
		currentFunction = EOPManager::ShellcodeFunctions[threadContext.first];

		//
		// Edit the RIP to point to the nexxt instruction of the shellcode.
		// Add the single step flag to break after the instruction is executed.
		//
		ExceptionInfo->ContextRecord->Rip = RCAST<DWORD64>(currentFunction[threadContext.second]);
		ExceptionInfo->ContextRecord->EFlags |= 0x100;

		//
		// Increment the instruction index in our thread context.
		//
		EOPManager::ThreadContext[currentThreadID].second++;

		//
		// Check if there are any more instructions to execute.
		//
		if (EOPManager::ThreadContext[currentThreadID].second == currentFunction.size())
		{
			DBGPRINT("Reached end of shellcode function 0x%llx, returning.", threadContext.first);

			//
			// Remove the single step flag and thread context.
			//
			ExceptionInfo->ContextRecord->EFlags &= ~0x100;
			EOPManager::ThreadContext.erase(EOPManager::ThreadContext.find(currentThreadID));
		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}
Exit:
	return EXCEPTION_CONTINUE_SEARCH;
}

/// <summary>
/// Attempt to find the given instruction inside an executable section
/// of any loaded module.
/// </summary>
/// <param name="Instruction">The instruction to search for.</param>
/// <param name="InstructionSize">The number of bytes for the instruction.</param>
/// <returns>An address to the instruction in a legitimate module. NULL if not found.</returns>
PVOID
EOPManager::FindInstruction (
	_In_ PVOID Instruction,
	_In_ SIZE_T InstructionSize
	)
{
	ULONG i;
	HMODULE* moduleList;
	HMODULE currentModule;
	DWORD cbNeeded;
	PVOID currentExecutableSection;
	SIZE_T currentExecutableSectionSize;
	ULONG currentOffset;
	ULONG64 currentMemoryAddress;

	UNWIND_HISTORY_TABLE historyTable;
	PRUNTIME_FUNCTION currentRuntimeFunction;
	BOOL badInstruction;
	BYTE codeIndex;
	PUNWIND_INFO currentUnwindInfo;
	BYTE currentOpcode;

	currentExecutableSection = NULL;
	currentExecutableSectionSize = 0;

	//
	// Retrieve the size required for the list of modules.
	//
	EnumProcessModules(GetCurrentProcess(), NULL, 0, &cbNeeded);
	moduleList = new HMODULE[cbNeeded / sizeof(HMODULE)];
	memset(moduleList, 0, cbNeeded);

	//
	// Retrieve the actual list of modules.
	//
	if (EnumProcessModules(GetCurrentProcess(), moduleList, cbNeeded, &cbNeeded) == FALSE)
	{
		DBGPRINT("Failed EnumProcessModules Error %i", GetLastError());
		goto Exit;
	}

	//
	// Enumerate each module to search for the given instruction.
	//
	for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
	{
		currentModule = moduleList[i];

		//
		// Enumerate the executable sections of the module.
		//
		while (FindNextExecSection(RCAST<PVOID>(currentModule), currentExecutableSection, currentExecutableSectionSize)
			   && currentExecutableSection)
		{
			//
			// Search the executable section for the instruction.
			//
			for (currentOffset = 0; currentOffset < currentExecutableSectionSize; currentOffset++)
			{
				currentMemoryAddress = RCAST<ULONG64>(currentExecutableSection) + currentOffset;

				//
				// Check if the current region of memory matches the instruction.
				//
				if (memcmp(RCAST<PVOID>(currentMemoryAddress), Instruction, InstructionSize) == 0)
				{
					//
					// If we are supporting SEH EOP, then we need to validate
					// that this region of memory is compatible.
					// Retrieve any unwinding information for this region.
					//
					currentRuntimeFunction = fRtlLookupFunctionEntry(currentMemoryAddress, RCAST<PDWORD64>(&currentModule), &historyTable);

					//
					// If currentRuntimeFunction is NULL then RtlDispatchException will default
					// to reading the return address from stack, which is fine.
					//
					if (currentRuntimeFunction)
					{
						//
						// Retrieve the unwind information structure for the address.
						// 
						currentUnwindInfo = RCAST<PUNWIND_INFO>(RCAST<ULONG64>(currentModule) + currentRuntimeFunction->UnwindInfoAddress);

						//
						// If there is unwind information for the address,
						// verify it does not contain incompatible operations.
						//
						badInstruction = FALSE;
						for (codeIndex = 0; codeIndex < currentUnwindInfo->CountOfCodes; codeIndex++)
						{
							currentOpcode = currentUnwindInfo->UnwindCode[codeIndex].UnwindOp;
							if (currentOpcode == UWOP_ALLOC_LARGE || currentOpcode == UWOP_ALLOC_SMALL)
							{
								//DBGPRINT("Ignoring instruction 0x%llx due to bad unwind opcode.", currentMemoryAddress);
								badInstruction = TRUE;
								break;
							}
						}

						//
						// If the instruction had a bad unwind info structure,
						// skip to the next memory address to check.
						//
						if (badInstruction)
						{
							continue;
						}
					}

					//
					// If we got this far, we found a valid instruction candidate.
					//
					delete[] moduleList;
					return RCAST<PVOID>(currentMemoryAddress);
				}
			}
		}
	}
Exit:
	if (moduleList)
	{
		delete[] moduleList;
	}
	return NULL;
}

/// <summary>
/// Create the internal structures for a given shellcode blob.
/// </summary>
/// <param name="ShellcodeInstructions">An array of instructions.</param>
/// <param name="InstructionCount">The number of instructions.</param>
/// <returns>An address that can be called to execute the shellcode.</returns>
PVOID
EOPManager::CreateShellcodeFunction (
	_In_ ShellcodeInstruction* ShellcodeInstructions,
	_In_ SIZE_T InstructionCount
	)
{
	std::vector<PVOID> instructions;
	std::vector<BYTE> currentShellcodeInstruction;
	ULONG i;
	PVOID instructionLocation;
	PVOID functionLocation;

	//
	// Enumerate each instruction for the given shellcode.
	//
	for (i = 0; i < InstructionCount; i++)
	{
		//
		// Attempt to find the current instruction inside of a legitimate module.
		//
		currentShellcodeInstruction = ShellcodeInstructions[i].GetInstruction();
		instructionLocation = EOPManager::FindInstruction(&currentShellcodeInstruction[0], currentShellcodeInstruction.size());
		if (instructionLocation == NULL)
		{
			//
			// If the instruction location is NULL, then we could not
			// find the current instruction in any legitimate module.
			//
			DBGPRINT("Shellcode instruction %i was not found in a legitimate module.", instructionLocation);
			return NULL;
		}

		//
		// If the instruction was found, add it to our list.
		//
		instructions.push_back(instructionLocation);
	}

	//
	// Next, find the location of an int3 instruction that
	// we aren't already using.
	//
	while((functionLocation = FindInstruction(CCAST<CHAR*>("\xCC"), 1)) &&
		  EOPManager::ShellcodeFunctions.find(functionLocation) != EOPManager::ShellcodeFunctions.end())
	{ }

	//
	// Update the internal shellcode function table with the
	// shellcode instructions.
	//
	EOPManager::ShellcodeFunctions[functionLocation] = instructions;

	return functionLocation;
}

/// <summary>
/// Register the internal exception handler.
/// </summary>
/// <returns>TRUE if exception handler registered successfully, FALSE otherwise.</returns>
BOOL
EOPManager::RegisterVectoredExceptionHandler (
	VOID
	)
{
	return AddVectoredExceptionHandler(ULONG_MAX, &EOPManager::GenericExceptionHandler) != NULL;
}

/// <summary>
/// This function is to be used when using EOP with SEH.
/// Place this function in the __except filter block.
/// </summary>
/// <param name="ExceptionInfo">Use GetExceptionInformation() for this argument.</param>
/// <returns>EXCEPTION_CONTINUE_EXECUTION or EXCEPTION_CONTINUE_SEARCH</returns>
LONG
EOPManager::SEHExceptionFilter (
	_Inout_ PEXCEPTION_POINTERS ExceptionInfo
	)
{
	//
	// Simply call the internal VEH handler with the SEH exception info.
	//
	return EOPManager::GenericExceptionHandler(ExceptionInfo);
}