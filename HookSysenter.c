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
		&ObjectAttrSource,//被初始化的OBJECT_ATTRIBUTES  
		pSourceFile,//对象名字字符串（文件路径）不能像在应用层那样直接用路径应写成 "\\??\\C:\\aa.txt"  
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,//前者表示名字不区分大小写，后者表示打开内核句柄  
		NULL,//用于相对打开的情况  
		NULL);//用于设置安全描述符  
	status = ZwCreateFile(
		&HSourceFile,
		GENERIC_READ,//申请的权限  
		&ObjectAttrSource,
		&io_status,//返回操作结果  
		NULL,
		FILE_ATTRIBUTE_NORMAL,//控制新建的文件属性  
		FILE_SHARE_READ,//共享访问  
		FILE_OPEN,//打开
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0
		);
	if (!NT_SUCCESS(status))//是否顺利打开  
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
	if (!NT_SUCCESS(status))//是否顺利打开  
	{
		DbgPrint("Open Destin File Error!");
		if (HSourceFile != NULL)
		{
			ZwClose(HSourceFile);
		}

		return status;
	}

	Length = 4 * 1024; //每次读取4KB  
	//为临时buffer分配内存  
	buffer = ExAllocatePoolWithTag(NonPagedPool, Length, MEM_TAG);

	/*打开文件后要进行循环读写文件操作*/
	while (1)
	{
		status = ZwReadFile(
			HSourceFile, NULL, NULL, NULL,
			&io_status,
			buffer,//存内容的buffer  
			Length,
			&offset,//要读取的文件的偏移  
			NULL);
		if (!NT_SUCCESS(status))
		{
			//如果状态为STATUS_END_OF_FILE说明文件读取成功结束  
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
		//获取实际读取到的长度  
		Length = io_status.Information;

		//把读取到的内容写入文件  
		status = ZwWriteFile(
			HDestinFile, NULL, NULL, NULL,
			&io_status,
			buffer, Length, &offset, NULL);
		if (!NT_SUCCESS(status))//是否顺利打开  
		{
			DbgPrint("Write File Error!");
			break;
		}
		//偏移量后移直至读取到文件结尾  
		offset.QuadPart += Length;
	}

	//退出前注意要手动释放资源  
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

	//初始化OBJECT_ATTRIBUTES结构
	InitializeObjectAttributes(&ObjectAttributes, stringKey, OBJ_CASE_INSENSITIVE, NULL, NULL);

	//打开注册表项
	status = ZwOpenKey(&hKey, GENERIC_ALL, &ObjectAttributes);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("打开注册表项失败！\n"));
		return status;
	}

	//初始化valueName
	RtlInitUnicodeString(&valueName, L"ImagePath");

	//获取实际查询的数据的大小
	status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, NULL, 0, &ulSize);
	if (status == STATUS_OBJECT_NAME_NOT_FOUND || ulSize == 0)
	{
		ZwClose(hKey);
		KdPrint(("注册表键值不存在！\n"));
		return status;
	}

	//分配实际查询所需的内存空间
	pkvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool(PagedPool, ulSize);

	//查询键值
	status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation,pkvpi, ulSize, &ulSize);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hKey);
		KdPrint(("查询注册表键值失败！\n"));
		return status;
	}

	//判断是否为REG_DWORD类型
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

	//关闭注册表句柄
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
		//再返回前修改堆栈里的数据
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

	KdPrint(("hook sysenter 位置%08X\n", ulHookSysenter));
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
