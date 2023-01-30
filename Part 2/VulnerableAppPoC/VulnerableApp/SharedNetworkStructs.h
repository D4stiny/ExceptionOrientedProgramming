#pragma once
#include <Windows.h>

typedef enum _PACKET_TYPE
{
	Leak,
	LeakResponse,
	UpdateHeapData,
	Overflow
} PACKET_TYPE;

typedef struct _BASE_PACKET
{
	PACKET_TYPE Type;
	ULONG Size;
} BASE_PACKET, *PBASE_PACKET;

typedef struct _LEAK_REQUEST
{
	BASE_PACKET Header;
	ULONG RequestedHeapSize;
} LEAK_REQUEST, *PLEAK_REQUEST;

typedef struct _LEAK_RESPONSE
{
	BASE_PACKET Header;
	ULONG_PTR NtdllBaseAddress;
	ULONG_PTR AllocatedHeapMemory;
} LEAK_RESPONSE, *PLEAK_RESPONSE;

typedef struct _UPDATE_HEAP_REQUEST
{
	BASE_PACKET Header;
	BYTE HeapData[1]; // Length determined by Header.Size - sizeof(BASE_PACKET)
} UPDATE_HEAP_REQUEST, *PUPDATE_HEAP_REQUEST;

typedef struct _OVERFLOW_REQUEST
{
	BASE_PACKET Header;
	BYTE OverflowBuffer[1]; // Length determined by Header.Size - sizeof(BASE_PACKET)
} OVERFLOW_REQUEST, *POVERFLOW_REQUEST;
