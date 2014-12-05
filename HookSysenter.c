#include "HookSysenter.h"
#include <ntifs.h>

#define MEM_TAG "test"

NTSYSAPI
NTSTATUS
NTAPI ZwQueryInformationProcess(
__in       HANDLE ProcessHandle,
__in       PROCESSINFOCLASS ProcessInformationClass,
__out      PVOID ProcessInformation,
__in       ULONG ProcessInformationLength,
__out_opt  PULONG ReturnLength
);

NTSTATUS MyCopyFile(
	PUNICODE_STRING pSourceFile,
	PUNICODE_STRING pDestinFile)
{
	HANDLE HSourceFile, HDestinFile;
	OBJECT_ATTRIBUTES ObjectAttrSource, ObjectAttrDestin;
	IO_STATUS_BLOCK  io_status = { 0 };

	LARGE_INTEGER offset = { 0 };
	PVOID buffer = NULL;
	ULONG Length;
	NTSTATUS status = STATUS_SUCCESS;


	InitializeObjectAttributes(
		&ObjectAttrSource,//����ʼ����OBJECT_ATTRIBUTES  
		pSourceFile,//���������ַ������ļ�·������������Ӧ�ò�����ֱ����·��Ӧд�� "\\??\\C:\\aa.txt"  
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,//ǰ�߱�ʾ���ֲ����ִ�Сд�����߱�ʾ���ں˾��  
		NULL,//������Դ򿪵����  
		NULL);//�������ð�ȫ������  
	status = ZwCreateFile(
		&HSourceFile,
		GENERIC_READ,//�����Ȩ��  
		&ObjectAttrSource,
		&io_status,//���ز������  
		NULL,
		FILE_ATTRIBUTE_NORMAL,//�����½����ļ�����  
		FILE_SHARE_READ,//�������  
		FILE_OPEN,//��
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0
		);
	if (!NT_SUCCESS(status))//�Ƿ�˳����  
	{
		DbgPrint("Open Source File Error!");
		return status;
	}


	InitializeObjectAttributes(
		&ObjectAttrDestin,
		pDestinFile,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
	status = ZwCreateFile(
		&HDestinFile,
		GENERIC_WRITE,
		&ObjectAttrDestin,
		&io_status,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_WRITE,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0
		);
	if (!NT_SUCCESS(status))//�Ƿ�˳����  
	{
		DbgPrint("Open Destin File Error!");
		if (HSourceFile != NULL)
		{
			ZwClose(HSourceFile);
		}

		return status;
	}

	Length = 4 * 1024; //ÿ�ζ�ȡ4KB  
	//Ϊ��ʱbuffer�����ڴ�  
	buffer = ExAllocatePoolWithTag(NonPagedPool, Length, MEM_TAG);

	/*���ļ���Ҫ����ѭ����д�ļ�����*/
	while (1)
	{
		status = ZwReadFile(
			HSourceFile, NULL, NULL, NULL,
			&io_status,
			buffer,//�����ݵ�buffer  
			Length,
			&offset,//Ҫ��ȡ���ļ���ƫ��  
			NULL);
		if (!NT_SUCCESS(status))
		{
			//���״̬ΪSTATUS_END_OF_FILE˵���ļ���ȡ�ɹ�����  
			if (status == STATUS_END_OF_FILE)
			{
				status = STATUS_SUCCESS;
				break;
			}
			else
			{
				DbgPrint("Read File Error!");
				break;
			}
		}
		//��ȡʵ�ʶ�ȡ���ĳ���  
		Length = io_status.Information;

		//�Ѷ�ȡ��������д���ļ�  
		status = ZwWriteFile(
			HDestinFile, NULL, NULL, NULL,
			&io_status,
			buffer, Length, &offset, NULL);
		if (!NT_SUCCESS(status))//�Ƿ�˳����  
		{
			DbgPrint("Write File Error!");
			break;
		}
		//ƫ��������ֱ����ȡ���ļ���β  
		offset.QuadPart += Length;
	}

	//�˳�ǰע��Ҫ�ֶ��ͷ���Դ  
	if (HSourceFile != NULL)
	{
		ZwClose(HSourceFile);
	}
	if (HDestinFile != NULL)
	{
		ZwClose(HDestinFile);
	}
	if (buffer != NULL)
	{
		ExFreePool(buffer);
	}
	return status;
}

#pragma INITCODE
NTSTATUS TetsKey(IN PUNICODE_STRING  stringKey)
{
	//UNICODE_STRING stringKey;
	OBJECT_ATTRIBUTES  ObjectAttributes;
	HANDLE hKey;
	UNICODE_STRING valueName;
	ULONG ulSize = 0;
	NTSTATUS status;
	PKEY_VALUE_PARTIAL_INFORMATION pkvpi;

	//��ʼ��OBJECT_ATTRIBUTES�ṹ
	InitializeObjectAttributes(&ObjectAttributes, stringKey, OBJ_CASE_INSENSITIVE, NULL, NULL);

	//��ע�����
	status = ZwOpenKey(&hKey, GENERIC_ALL, &ObjectAttributes);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("��ע�����ʧ�ܣ�\n"));
		return status;
	}

	//��ʼ��valueName
	RtlInitUnicodeString(&valueName, L"ImagePath");

	//��ȡʵ�ʲ�ѯ�����ݵĴ�С
	status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, NULL, 0, &ulSize);
	if (status == STATUS_OBJECT_NAME_NOT_FOUND || ulSize == 0)
	{
		ZwClose(hKey);
		KdPrint(("ע����ֵ�����ڣ�\n"));
		return status;
	}

	//����ʵ�ʲ�ѯ������ڴ�ռ�
	pkvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool(PagedPool, ulSize);

	//��ѯ��ֵ
	status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation,pkvpi, ulSize, &ulSize);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hKey);
		KdPrint(("��ѯע����ֵʧ�ܣ�\n"));
		return status;
	}

	//�ж��Ƿ�ΪREG_DWORD����
	/*if (pkvpi->Type == REG_DWORD && pkvpi->DataLength == sizeof(ULONG))
	{
		PULONG a = (PULONG)pkvpi->Data;
		KdPrint(("%d\n", *a));
	}*/
	if (pkvpi->Type == REG_EXPAND_SZ)
	{
		UNICODE_STRING usDriverPath;
		UNICODE_STRING usDesDriverPath;
		LPWSTR wszDriverPath;
		LPWSTR pwsDriverName;
		WCHAR wszSrcBuffer[500] = { L"\\??\\c:\\windows\\" };
		WCHAR wszDesBuffer[500] = { L"\\??\\c:" };

		wszDriverPath = (WCHAR *)pkvpi->Data;

		pwsDriverName = wcsrchr(wszDriverPath, L'\\');
		if (pwsDriverName && pkvpi->DataLength < 450)
		{
			wcscat(wszDesBuffer, pwsDriverName);
			RtlInitUnicodeString(&usDesDriverPath, wszDesBuffer);

			if (_wcsnicmp(wszDriverPath, L"system32", 8) == 0)
			{
				wcscat(wszSrcBuffer, wszDriverPath);
				RtlInitUnicodeString(&usDriverPath, wszSrcBuffer);

			}
			else
			{
				RtlInitUnicodeString(&usDriverPath, wszDriverPath);
			}
			MyCopyFile(&usDriverPath, &usDesDriverPath);
			//KdPrint(("asdf\n"));
			//KdPrint(("%ws\n", a));
		}
	}
	else
	{
		KdPrint(("error\n"));
	}

	//�ر�ע�����
	ZwClose(hKey);
	ExFreePoolWithTag(pkvpi, MEM_TAG);

	return status;
}



NTSTATUS myZwLoadDriver(
IN PUNICODE_STRING  DriverServiceName
)
{
	KdPrint(("driver name:%ws\n", DriverServiceName->Buffer));

	TetsKey(DriverServiceName);
}

ULONG gNtLoadDriver;
NTSTATUS __declspec(naked) ZwLoadDriverStub(
IN PUNICODE_STRING  DriverServiceName
)
{
	_asm
	{
		mov edi, edi
		push ebp
		mov ebp, esp
		pushad
		pushfd
	}
	myZwLoadDriver(DriverServiceName);
	_asm
	{
		//mov[esp + 0x20], eax
		popfd
		popad
		mov esp, ebp
		pop ebp
		//retn
		jmp gNtLoadDriver
	}
}


ULONG display(ULONG ServiceTableBase,ULONG FuncIndex,ULONG OrigFuncAddress)
{
	if(ServiceTableBase == (ULONG)KeServiceDescriptorTable->Base)
	{
		if (FuncIndex == 97)	//97 NtLoadDriver
		{
			gNtLoadDriver = OrigFuncAddress;
			return ZwLoadDriverStub;
		}
	}
	return OrigFuncAddress;
}

ULONG ulHookSysenter;
VOID __declspec(naked) MyKiFastCallEntry()
{
	_asm
	{

		pushad
		pushfd
		
		push  ebx
		push  eax
		push  edi
		call  display
		//�ٷ���ǰ�޸Ķ�ջ�������
		mov    [esp+0x14],eax
		popfd
		popad

		sub     esp,ecx
		shr     ecx,2
		jmp ulHookSysenter
	}
}

VOID SetSysenterHook()
{
	LONG pfKiFastCallEntry;
	_asm
	{
		mov ecx, 0x176
		rdmsr
		mov pfKiFastCallEntry, eax
	}
	KdPrint(("KiFastCallEntry:%08X\n", pfKiFastCallEntry));
	ulHookSysenter = SundayFind("\x2B\xE1\xC1\xE9\x02\x8B\xFC", 7, (PCHAR)pfKiFastCallEntry, 1000);
	if(-1 == ulHookSysenter)
		return ;

	KdPrint(("hook sysenter λ��%08X\n", ulHookSysenter));
	SetHook(ulHookSysenter, (ULONG)(MyKiFastCallEntry));
	ulHookSysenter += 5;
}

VOID UnSysenterHook()
{
	UnHook((PUCHAR)"\x2B\xE1\xC1\xE9\x02\x8B\xFC", 7, (PVOID)(ulHookSysenter-5));
}

VOID SetHook(ULONG ulHookAddr, ULONG ulHookProc)
{
	CloseWP();
	*(PUCHAR)ulHookAddr = 0xE9;
	*(PULONG)(ulHookAddr+1) = ulHookProc - ulHookAddr - 5;
	OpenWP();
}

VOID UnHook(PUCHAR pat, ULONG patLength, PVOID ulHookAddr)
{
	CloseWP();
	memcpy(ulHookAddr, pat, patLength);
	OpenWP();
}

ULONG SetSSDTHook(PULONG ServiceTableBase, ULONG index, ULONG ulHookProc)
{
	ULONG pfAddr = ServiceTableBase[index];
	CloseWP();
	ServiceTableBase[index] = ulHookProc;
	OpenWP();
	return pfAddr;
}

VOID UnSSDTHook(PULONG ServiceTableBase, ULONG index, ULONG ulHookProc)
{
	CloseWP();
	ServiceTableBase[index] = ulHookProc;
	OpenWP();
}

ULONG MmGetSystemFunAddress(PWSTR Buffer)
{
	UNICODE_STRING SystemRoutineName;
	RtlInitUnicodeString(&SystemRoutineName, Buffer);
	return (ULONG)MmGetSystemRoutineAddress(&SystemRoutineName);
}


ULONG SundayFind(PUCHAR pat, ULONG patLength, PUCHAR text, ULONG textLength)
{
	UCHAR MovDistance[0x100];
	ULONG i = 0;
	PUCHAR tx = text;

	if(textLength <= 0)
		return -1;

	memset(MovDistance, patLength+1, 0x100);
	for(i = 0; i < patLength; i++)
	{
		MovDistance[pat[i]] = (UCHAR)(patLength - i);
	}
	
	while(tx+patLength <= text+textLength)
	{
		UCHAR *p = pat, *t = tx;
		ULONG i = 0;
		for(i = 0; i < patLength; i++)
		{
			if(p[i] != t[i])
				break;
		}
		if(i == patLength)
			return (ULONG)tx;
		if(tx+patLength == text+textLength)
			return -1;
		tx += MovDistance[tx[patLength]];
	}
	return -1;
}
