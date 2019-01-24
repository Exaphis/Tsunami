#pragma once
#include <ntifs.h>

// Source: https://github.com/mq1n/EasyRing0/blob/master/Tutorial_6_ShareMem_Communication_SYS/helper.h

NTSTATUS CreateStandardSCAndACL(OUT PSECURITY_DESCRIPTOR* SecurityDescriptor, OUT PACL* Acl);
NTSTATUS GrantAccess(HANDLE hSection, IN PACL StandardAcl);