#include "Exports.h"

#include <stdio.h>

FARPROC WINAPI GetExport(const HMODULE hModule, const char *pName)
{
    FARPROC pRetProc = (FARPROC)GetProcAddress(hModule, pName);
    if(pRetProc == NULL)
    {
        printf("Could not get address of %s. Last error = %X\n", pName, GetLastError());
    }

    return pRetProc;
}

const bool GetFunctions(void)
{
    HMODULE hBCryptDll = GetModuleHandle(L"bcrypt.dll");
    HMODULE hNCryptDll = GetModuleHandle(L"ncrypt.dll");
    if(hBCryptDll == NULL)
    {
        printf("Could not get handle to Bcrypt.dll. Last error = %X\n", GetLastError());
        return false;
    }
    if(hNCryptDll == NULL)
    {
        printf("Could not get handle to Bcrypt.dll. Last error = %X\n", GetLastError());
        return false;
    }
    printf("Module handle: %016X\n", hBCryptDll);

    BCryptHashDataFnc = (pBCryptHashData)GetExport(hBCryptDll, "BCryptHashData");
    SslEncryptPacketFnc = (pSslEncryptPacket)GetExport(hNCryptDll, "SslEncryptPacket");

    return ((BCryptHashDataFnc != NULL) && (SslEncryptPacketFnc != NULL));
}