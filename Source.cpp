#define _CRT_SECURE_NO_WARNINGS //Ignore warning about freopen

#include <cstdio>
#include <Windows.h>

#include "Exports.h"
#include "Hooks.h"

PVOID pExceptionHandler = NULL;
pBCryptHashData BCryptHashDataFnc = NULL;
pSslEncryptPacket SslEncryptPacketFnc = NULL;

const bool AddBreakpoint(void *pAddress)
{
    SIZE_T dwSuccess = 0;

    MEMORY_BASIC_INFORMATION memInfo = { 0 };
    dwSuccess = VirtualQuery(pAddress, &memInfo, sizeof(MEMORY_BASIC_INFORMATION));
    if(dwSuccess == 0)
    {
        printf("VirtualQuery failed on %016X. Last error = %X\n", pAddress, GetLastError());
        return false;
    }

    DWORD dwOldProtections = 0;
    dwSuccess = VirtualProtect(pAddress, sizeof(DWORD_PTR), memInfo.Protect | PAGE_GUARD, &dwOldProtections);
    if(dwSuccess == 0)
    {
        printf("VirtualProtect failed on %016X. Last error = %X\n", pAddress, GetLastError());
        return false;
    }

    return true;
}

const bool SetBreakpoints(void)
{
    bool bRet = AddBreakpoint(BCryptHashDataFnc);
    bRet &= AddBreakpoint(SslEncryptPacketFnc);

    return bRet;
}

LONG CALLBACK VectoredHandler(EXCEPTION_POINTERS *pExceptionInfo)
{
    if(pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
    {        
        pExceptionInfo->ContextRecord->EFlags |= 0x100;

        DWORD_PTR dwExceptionAddress = (DWORD_PTR)pExceptionInfo->ExceptionRecord->ExceptionAddress;
        CONTEXT *pContext = pExceptionInfo->ContextRecord;

        if(dwExceptionAddress == (DWORD_PTR)SslEncryptPacketFnc)
        {
            DWORD_PTR *pdwParametersBase = (DWORD_PTR *)(pContext->Rsp + 0x28);
            SslEncryptPacketHook((NCRYPT_PROV_HANDLE)pContext->Rcx, (NCRYPT_KEY_HANDLE)pContext->Rdx, (PBYTE *)pContext->R8, (DWORD)pContext->R9,
                (PBYTE)(*(pdwParametersBase)), (DWORD)(*(pdwParametersBase + 1)), (DWORD *)(*(pdwParametersBase + 2)), (ULONGLONG)(*(pdwParametersBase + 3)),
                (DWORD)(*(pdwParametersBase + 4)), (DWORD)(*(pdwParametersBase + 5)));
        }
        else if(dwExceptionAddress == (DWORD_PTR)BCryptHashDataFnc)
        {
            BCryptHashDataHook((BCRYPT_HASH_HANDLE)pContext->Rcx, (PUCHAR)pContext->Rdx, (ULONG)pContext->R8, (ULONG)pContext->R9);
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }
    
    if(pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        (void)SetBreakpoints();
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch(dwReason)
    {
    case DLL_PROCESS_ATTACH:
        (void)DisableThreadLibraryCalls(hModule);
        if(AllocConsole())
        {
            freopen("CONOUT$", "w", stdout);
            SetConsoleTitle(L"Console");
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            printf("DLL loaded.\n");
        }
        if(GetFunctions())
        {
            pExceptionHandler = AddVectoredExceptionHandler(TRUE, VectoredHandler);
            if(SetBreakpoints())
            {
                printf("BCryptHashData: %016X\n"
                    "SslEncryptPacket: %016X\n",
                    BCryptHashDataFnc, SslEncryptPacketFnc);
            }
            else
            {
                printf("Could not set initial breakpoints.\n");
            }
        }
        break;

    case DLL_PROCESS_DETACH:
        //Clean up here usually
        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}