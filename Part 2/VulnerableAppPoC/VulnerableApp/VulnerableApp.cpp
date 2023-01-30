#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

#include "SharedNetworkStructs.h"

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"

__declspec(noinline)
VOID
ProcessPacket (
    SOCKET ClientSocket,
    PBASE_PACKET CompletePacket
    )
{
    char overflowBuffer[16];
    ULONG packetType;
    PLEAK_REQUEST leakRequestPacket;
    PUPDATE_HEAP_REQUEST updateHeapPacket;
    POVERFLOW_REQUEST overflowRequestPacket;
    LEAK_RESPONSE leakResponse;
    static PVOID heapMemory = NULL;
    

    packetType = CompletePacket->Type;
    leakResponse.Header.Type = PACKET_TYPE::LeakResponse;
    leakResponse.Header.Size = sizeof(LEAK_RESPONSE);

    switch (packetType)
    {
        case PACKET_TYPE::Leak:
            leakRequestPacket = reinterpret_cast<PLEAK_REQUEST>(CompletePacket);
            
            //
            // Allocate some heap memory given a size.
            // Note that this will cause a memory leak,
            // we never free it.
            //
            if (heapMemory == NULL)
            {
                heapMemory = malloc(leakRequestPacket->RequestedHeapSize);
            }
            leakResponse.AllocatedHeapMemory = reinterpret_cast<ULONG_PTR>(heapMemory);

            //
            // Retrieve the NTDLL base address.
            //
            leakResponse.NtdllBaseAddress = reinterpret_cast<ULONG_PTR>(GetModuleHandleA("ntdll.dll"));

            //
            // Send the response.
            //
            send(ClientSocket, reinterpret_cast<const char*>(&leakResponse), leakResponse.Header.Size, 0);
            break;
        case PACKET_TYPE::UpdateHeapData:
            updateHeapPacket = reinterpret_cast<PUPDATE_HEAP_REQUEST>(CompletePacket);
            
            //
            // Copy the data into the heap.
            // Obviously the client can lie about size and
            // copy some OOB data into the heap memory.
            //
            if (heapMemory)
            {
                memcpy(heapMemory, updateHeapPacket->HeapData, updateHeapPacket->Header.Size - sizeof(BASE_PACKET));
            }
            break;
        case PACKET_TYPE::Overflow:
            overflowRequestPacket = reinterpret_cast<POVERFLOW_REQUEST>(CompletePacket);

            //
            // Trigger an overflow and exception.
            //
            memcpy(overflowBuffer, overflowRequestPacket->OverflowBuffer, overflowRequestPacket->Header.Size - sizeof(BASE_PACKET));
            *reinterpret_cast<ULONG*>(0xDEADBEEF) = 0xCAFEBABE;

            //
            // So that the overflowBuffer isn't optimized out.
            // We should never reach here.
            //
            printf("%i\n", strlen(overflowBuffer));
            break;
    }
}


VOID
NetworkLoop (
    SOCKET ClientSocket
    )
{
    int result;
    BASE_PACKET currentHeader;
    PBASE_PACKET currentPacket;
    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;

    // Receive until the peer shuts down the connection
    do {
        //
        // Receive a base packet structure from the client.
        //
        result = recv(ClientSocket, reinterpret_cast<char*>(&currentHeader), sizeof(currentHeader), 0);
        if (result != sizeof(currentHeader))
        {
            if (result == 0)
            {
                printf("[~] Client closed connection.\n");
            }
            else
            {
                printf("[-] Unknown error while recv'ing (result %i): %i.\n", result, WSAGetLastError());
            }
            break;
        }

        //
        // Allocate space for the entire packet.
        // Obviously we are blindly trusting the size here.
        //
        currentPacket = reinterpret_cast<PBASE_PACKET>(malloc(currentHeader.Size));
        if (currentPacket == NULL)
        {
            printf("[-] Failed to allocate 0x%X bytes for packet.\n", currentHeader.Size);
            break;
        }

        //
        // Copy the base packet header we already have into this region.
        //
        memcpy(currentPacket, &currentHeader, sizeof(currentHeader));

        //
        // recv the rest of the packet.
        //
        result = recv(ClientSocket, reinterpret_cast<char*>(reinterpret_cast<ULONG_PTR>(currentPacket) + sizeof(BASE_PACKET)), (currentHeader.Size - sizeof(BASE_PACKET)), 0);
        if (result != currentHeader.Size - sizeof(BASE_PACKET))
        {
            if (result == 0)
            {
                printf("[~] Client closed connection.\n");
            }
            else
            {
                printf("[-] Unknown error while recv'ing: %i.\n", WSAGetLastError());
            }
            break;
        }

        //
        // Process the given packet.
        //
        ProcessPacket(ClientSocket, currentPacket);

        //
        // Free the packet memory.
        //
        free(currentPacket);
    } while (result > 0);

    shutdown(ClientSocket, SD_SEND);
    closesocket(ClientSocket);
}

int __cdecl main(void)
{
    WSADATA wsaData;
    int iResult;

    SOCKET ListenSocket = INVALID_SOCKET;
    //SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfo* result = NULL;
    struct addrinfo hints;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Create a SOCKET for the server to listen for client connections.
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Setup the TCP listening socket
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    do {
        // Accept a client socket
        SOCKET ClientSocket = accept(ListenSocket, NULL, NULL);
        if (ClientSocket == INVALID_SOCKET) {
            printf("accept failed with error: %d\n", WSAGetLastError());
            continue;
        }

        //
        // Enter our network loop for the connection.
        //
        NetworkLoop(ClientSocket);
    } while (TRUE);

    // No longer need server socket
    closesocket(ListenSocket);

    // cleanup
    WSACleanup();

    return 0;
}