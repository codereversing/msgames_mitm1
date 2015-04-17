#include "Hooks.h"
#include "Exports.h"

#include <stdio.h>

void WINAPI BCryptHashDataHook(BCRYPT_HASH_HANDLE hHash, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags)
{
    printf("--- BCryptHashData ---\n"
        "Input: %.*s\n",
        cbInput, pbInput);
}

void WINAPI SslEncryptPacketHook(NCRYPT_PROV_HANDLE hSslProvider, NCRYPT_KEY_HANDLE hKey, PBYTE *pbInput, DWORD cbInput,
                              PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, ULONGLONG SequenceNumber, DWORD dwContentType, DWORD dwFlags)
{
    printf("--- SslEncryptPacket ---\n"
        "Input: %.*s\n",
        cbInput, pbInput);
}