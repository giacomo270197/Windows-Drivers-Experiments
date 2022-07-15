#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

extern "C" {
	DRIVER_INITIALIZE DriverEntry;
	NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
	NTSTATUS TracerMiniFilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
	NTSTATUS PfltInstanceSetupCallback(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags, DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType);
	NTSTATUS TracerMiniFilterQueryTeardown(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);
	VOID TracerMiniFilterInstanceTeardownStart(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_TEARDOWN_FLAGS Flags);
	VOID TracerMiniFilterInstanceTeardownComplete(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_TEARDOWN_FLAGS Flags);
	FLT_PREOP_CALLBACK_STATUS TracerCreateLog(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);

	NTSTATUS ZwQueryInformationProcess(HANDLE ProcessHandle,PROCESSINFOCLASS ProcessInformationClass,PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, TracerMiniFilterUnload)
#pragma alloc_text(PAGE, PfltInstanceSetupCallback)
#pragma alloc_text(PAGE, TracerMiniFilterQueryTeardown)
#pragma alloc_text(PAGE, TracerMiniFilterInstanceTeardownStart)
#pragma alloc_text(PAGE, TracerMiniFilterInstanceTeardownComplete)
#endif

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE, 0, TracerCreateLog, nullptr},
	{ IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	0,
	nullptr,
	Callbacks,
	TracerMiniFilterUnload,
	PfltInstanceSetupCallback,
	TracerMiniFilterQueryTeardown,
	TracerMiniFilterInstanceTeardownStart,
	TracerMiniFilterInstanceTeardownComplete
};

PFLT_FILTER filterHandle;


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {

	UNREFERENCED_PARAMETER(RegistryPath);
	
	NTSTATUS status;
	
	status = FltRegisterFilter(DriverObject, &FilterRegistration, &filterHandle);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to register filesystem mini-filter\n"));
		return status;
	}
	
	status = FltStartFiltering(filterHandle);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to start filtering\n"));
		FltUnregisterFilter(filterHandle);
		return status;
	}
	
	return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS TracerCreateLog(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	
	NTSTATUS status;
	if (Data->RequestorMode == KernelMode) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// Get the process name
	PEPROCESS process = PsGetThreadProcess(Data->Thread);
	if (process == nullptr) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	HANDLE hProcess;
	status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, nullptr, 0, nullptr, KernelMode, &hProcess);
	if (!NT_SUCCESS(status)){
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	
	ULONG size = 1024;
	auto processName = (UNICODE_STRING*)ExAllocatePool(PagedPool, size);
	if (processName == nullptr) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	RtlZeroMemory(processName, size);
	
	status = ZwQueryInformationProcess(hProcess, ProcessImageFileName, processName, size - sizeof(WCHAR), nullptr);
	if (!NT_SUCCESS(status) || (processName->Length < 0)) {
		ExFreePool(processName);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (wcsstr(processName->Buffer, L"notepad.exe") == nullptr) {
		ExFreePool(processName);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// Get the filename the handle is being opened to
	FLT_FILE_NAME_OPTIONS nameOptions = FLT_FILE_NAME_NORMALIZED;
	PFLT_FILE_NAME_INFORMATION fileNameInformation = nullptr;
	status = FltGetFileNameInformation(Data, nameOptions, &fileNameInformation);
	if (!NT_SUCCESS(status)) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	status = FltParseFileNameInformation(fileNameInformation);
	if (!NT_SUCCESS(status)) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	const auto& createParams = Data->Iopb->Parameters.Create;
	auto success = NT_SUCCESS(Data->IoStatus.Status);
	auto isDirectory = fileNameInformation->Extension.Length == 0;
	if (success) {
		if (!isDirectory) {
			bool readAccess = createParams.SecurityContext->DesiredAccess & FILE_READ_DATA;
			bool writeAccess = createParams.SecurityContext->DesiredAccess & FILE_WRITE_DATA;
			bool executeAccess = createParams.SecurityContext->DesiredAccess & FILE_EXECUTE;
			bool success = NT_SUCCESS(Data->IoStatus.Status);
			KdPrint(("'%wZ', Read: %s Write: %s Execute: %s Success: %s", fileNameInformation->Name, readAccess ? "true" : "false", writeAccess ? "true" : "false", executeAccess ? "true" : "false", success ? "true" : "false"));
		}
	}
	else {
		KdPrint(("Process failed to open a handle to '%wZ'", fileNameInformation->Name));
	}

	ExFreePool(processName);
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS TracerMiniFilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
	UNREFERENCED_PARAMETER(Flags);
	PAGED_CODE();
	FltUnregisterFilter(filterHandle);
	return STATUS_SUCCESS;

}

NTSTATUS PfltInstanceSetupCallback(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags, DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType) {
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);
	PAGED_CODE();
	return STATUS_SUCCESS;
}

NTSTATUS TracerMiniFilterQueryTeardown(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags) {
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	PAGED_CODE();
	return STATUS_SUCCESS;
}

VOID TracerMiniFilterInstanceTeardownStart(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_TEARDOWN_FLAGS Flags) {
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	PAGED_CODE();
}

VOID TracerMiniFilterInstanceTeardownComplete(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_TEARDOWN_FLAGS Flags) {
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	PAGED_CODE();
}