/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2022
 */
#include "EOPManager.h"

//
// Extremely simple shellcode to demonstrate execution.
//
ShellcodeInstruction exampleShellcode[] = {
	einstr(0xB8, 0x03, 0x00, 0x00, 0x00),	// mov eax, 0x3
	einstr(0xC3)							// ret
};
//
// Prototype for the shellcode above.
//
typedef int(__fastcall* func_t)();

/// <summary>
/// Wrapper function to call shellcode with SEH.
/// </summary>
/// <param name="Function">The function to call.</param>
/// <returns>The result of the shellcode (should be 3 for the example).</returns>
INT SEHWrapperFunc(func_t Function)
{
	__try {
		return Function();
	}
	//
	// This is where the magic happens.
	//
	__except (EOPManager::SEHExceptionFilter(GetExceptionInformation()))
	{}
}

int main()
{
	EOPManager eopManager;
	PVOID shellcodeFunction;
	func_t testFunction;
	int result;

	//
	// Check for a debugger as I'm worried
	// folks will run this directly with VS.
	//
	if (IsDebuggerPresent())
	{
		DBGPRINT("Warning! You are running this PoC with a debugger, which will likely interfere with the EOP exception handler. Run directly if you encounter issues.");
		__debugbreak();
	}

	//
	// First, let's create the internal structures for the shellcode.
	//
	shellcodeFunction = eopManager.CreateShellcodeFunction(exampleShellcode);
	testFunction = RCAST<func_t>(shellcodeFunction);
	if (shellcodeFunction == NULL)
	{
		DBGPRINT("Failed to create the internal structures for the given shellcode.");
		return 0;
	}

	printf("Successfully created shellcode function at 0x%llx.\n", shellcodeFunction);

	//
	// Test the function with SEH.
	//
	printf("Testing EOP with SEH...\n");
	result = SEHWrapperFunc(testFunction);
	if (result == 3)
	{
		printf("Successfully executed example shellcode using SEH! Result = %i\n", result);
	}
	else
	{
		printf("Received unrecognized result %i when testing with SEH.\n", result);
	}

	//
	// Test the function with VEH.
	// We don't need to do anything special besides
	// registering the VEH.
	//
	printf("Testing EOP with VEH...\n");
	eopManager.RegisterVectoredExceptionHandler();
	result = testFunction();
	if (result == 3)
	{
		printf("Successfully executed example shellcode using VEH! Result = %i\n", result);
	}
	else
	{
		printf("Received unrecognized result %i when testing with VEH.\n", result);
	}
	
	printf("Done.\n");
	return 0;
}