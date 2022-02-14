#pragma once
#include <Windows.h>

#ifdef _DEBUG
#include <cstdio>
#define DBGPRINT(msg, ...) printf(msg"\n", __VA_ARGS__)
#else
#define DBGPRINT(x, ...)
#endif

#define RCAST reinterpret_cast
#define SCAST static_cast
#define CCAST const_cast

#define FlagOn(_F,_SF) ((_F) & (_SF))

typedef union _UNWIND_CODE {
	struct {
		BYTE CodeOffset;
		BYTE UnwindOp : 4;
		BYTE OpInfo : 4;
	};
	USHORT FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _UNWIND_INFO {
	BYTE Version : 3;
	BYTE Flags : 5;
	BYTE SizeOfProlog;
	BYTE CountOfCodes;  //so the beginning of ExceptionData is known as they're both FAMs
	BYTE FrameRegister : 4;
	BYTE FrameOffset : 4;
	UNWIND_CODE UnwindCode[1];
	union {
		//
		// If (Flags & UNW_FLAG_EHANDLER)
		//
		OPTIONAL ULONG ExceptionHandler;
		//
		// Else if (Flags & UNW_FLAG_CHAININFO)
		//
		OPTIONAL ULONG FunctionEntry;
	};
	//
	// If (Flags & UNW_FLAG_EHANDLER)
	//
	OPTIONAL ULONG ExceptionData[];
} UNWIND_INFO, * PUNWIND_INFO;

#define UNWIND_HISTORY_TABLE_NONE 0
#define UWOP_ALLOC_LARGE 1
#define UWOP_ALLOC_SMALL 2

typedef PRUNTIME_FUNCTION(NTAPI* RtlLookupFunctionEntry_t)(DWORD64, PDWORD64, PUNWIND_HISTORY_TABLE);