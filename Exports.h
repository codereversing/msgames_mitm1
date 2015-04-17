#pragma once

#include <Windows.h>

typedef NTSTATUS (WINAPI *pBCryptHashData)(BCRYPT_HASH_HANDLE hHash, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags);

typedef SECURITY_STATUS (WINAPI *pSslEncryptPacket)(NCRYPT_PROV_HANDLE hSslProvider, NCRYPT_KEY_HANDLE hKey, PBYTE *pbInput, DWORD cbInput,
                              PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, ULONGLONG SequenceNumber, DWORD dwContentType, DWORD dwFlags);

extern pBCryptHashData BCryptHashDataFnc;
extern pSslEncryptPacket SslEncryptPacketFnc;

FARPROC WINAPI GetExport(const HMODULE hModule, const char *pName);
const bool GetFunctions(void);