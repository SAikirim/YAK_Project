#include <ntddk.h>
#include <ntdef.h>

extern NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

PVOID GetPeb(HANDLE ProcessHandle)
{
    NTSTATUS status;
    PROCESS_BASIC_INFORMATION pbi;
    PVOID pPeb;

    memset(&pbi, 0, sizeof(pbi));

    status = pNtQueryInformationProcess(
        ProcessHandle,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        NULL);

    pPeb = NULL;

    if (NT_SUCCESS(status))
    {
        pPeb = pbi.PebBaseAddress;
    }

    return pPeb;
}