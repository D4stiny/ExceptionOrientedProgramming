/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2022
 */
#pragma once
#include "ntdef.h"
#include <map>
#include <vector>
#include <psapi.h>

class ShellcodeInstruction
{
	/// <summary>
	/// The bytes that make up the instruction.
	/// </summary>
	std::vector<BYTE> Instruction;
public:
	ShellcodeInstruction (
		std::vector<BYTE> InstructionBytes
		) : Instruction(InstructionBytes) {}

	std::vector<BYTE> GetInstruction (
		VOID
		)
	{
		return this->Instruction;
	}
};

/// <summary>
/// This macro allows you to define instructions with ease.
/// i.e einstr({0x90}) = nop
/// </summary>
#define einstr(...) ShellcodeInstruction({__VA_ARGS__})

class EOPManager
{
	/// <summary>
	/// This map tracks the instructions to use for a given "shellcode function".
	/// 
	/// The key is the int3 instruction that triggers the given "shellcode function".
	/// 
	/// The vector contains a list of addresses that point to the instructions that
	/// make up the given shellcode.
	/// </summary>
	static std::map<PVOID, std::vector<PVOID>> ShellcodeFunctions;

	/// <summary>
	/// This map tracks the current instruction being executed for a given "shellcode function".
	/// 
	/// The key is the ID of the thread.
	/// 
	/// The pair contains the int3 instruction that triggers the given function and
	/// the index of the current instruction (index applies to ShellcodeFunctions vector).
	/// </summary>
	static std::map<DWORD, std::pair<PVOID, ULONG>> ThreadContext;

	static BOOL FindNextExecSection (
		_In_ PVOID ImageBase,
		_Inout_ PVOID& ExecSectionBase,
		_Inout_ SIZE_T& ExecSectionSize
		);
	static LONG GenericExceptionHandler (
		_Inout_ PEXCEPTION_POINTERS ExceptionInfo
		);
	static PVOID FindInstruction (
		_In_ PVOID Instruction,
		_In_ SIZE_T InstructionSize
		);
	static PVOID CreateShellcodeFunction (
		_In_ ShellcodeInstruction* ShellcodeInstructions,
		_In_ SIZE_T InstructionCount
	);
public:
	template<SIZE_T N>
	static PVOID CreateShellcodeFunction (
		_In_ ShellcodeInstruction (&Shellcode)[N]
		) {
		return EOPManager::CreateShellcodeFunction(Shellcode, N);
	}

	static BOOL RegisterVectoredExceptionHandler (
		VOID
		);
	static LONG SEHExceptionFilter (
		_Inout_ PEXCEPTION_POINTERS ExceptionInfo
		);

};

extern RtlLookupFunctionEntry_t fRtlLookupFunctionEntry;