/*++

Copyright (c) 1992  Microsoft Corporation
 
Module Name:
 
	passthru.c

Abstract:

	Ndis Intermediate Miniport driver sample. This is a passthru driver.

Author:

Environment:


Revision History:


--*/


#include "precomp.h"
#include <ntddk.h>

#include "passthru.h"
#include <stdio.h>

#pragma hdrstop

#pragma NDIS_INIT_FUNCTION(DriverEntry)

NDIS_PHYSICAL_ADDRESS			HighestAcceptableMax = NDIS_PHYSICAL_ADDRESS_CONST(-1, -1);
NDIS_HANDLE						ProtHandle = NULL;
NDIS_HANDLE						DriverHandle = NULL;
NDIS_MEDIUM						MediumArray[3] =
									{
										NdisMedium802_3,	// Ethernet
										NdisMedium802_5,	// Token-ring
										NdisMediumFddi		// Fddi
									};


PADAPT  pAdaptList=NULL;

GLOBAL Globals;

PASS_PACKET	gPackets[MAX_PASS_PACKET];

char theLog[50000];

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, NFilterUnload)
#endif

void InitLog()
{
	memset(theLog, 0, sizeof(theLog));
}

void AddLog(char *str)
{
	if (strlen(theLog)+strlen(str) > sizeof(theLog))
		return;
	strcat(theLog, str);
}

void WriteLog(char *str)
{
	NTSTATUS state;
	HANDLE handle;
	IO_STATUS_BLOCK	block;

	UNICODE_STRING Name;
	OBJECT_ATTRIBUTES	attr;
	LARGE_INTEGER	AllocSize;

	AllocSize.QuadPart = FILE_USE_FILE_POINTER_POSITION;

	RtlInitUnicodeString(&Name, LOG_FILE_NAME);

	InitializeObjectAttributes(
			&attr, //OUT POBJECT_ATTRIBUTES  InitializedAttributes,
			&Name, //IN PUNICODE_STRING  ObjectName,
			OBJ_OPENIF, //IN ULONG  Attributes,
			NULL, //IN HANDLE  RootDirectory,
			NULL //IN PSECURITY_DESCRIPTOR  SecurityDescriptor
		);
		
    state = ZwCreateFile(
			&handle, //OUT PHANDLE FileHandle,
			FILE_APPEND_DATA | SYNCHRONIZE ,//IN ACCESS_MASK DesiredAccess,
			&attr,//IN POBJECT_ATTRIBUTES ObjectAttributes,
			&block, //OUT PIO_STATUS_BLOCK IoStatusBlock,
			NULL,//&AllocSize,//IN PLARGE_INTEGER AllocationSize OPTIONAL,
			FILE_ATTRIBUTE_NORMAL,//IN ULONG FileAttributes,
			FILE_SHARE_READ | FILE_SHARE_WRITE,//IN ULONG ShareAccess,
			FILE_OPEN_IF,//IN ULONG Disposition,
			FILE_NON_DIRECTORY_FILE,//IN ULONG CreateOptions,
			0,
			0
        ) ;
	
	if (strlen(theLog)>0)
	{
		state = ZwWriteFile(
				handle, //IN HANDLE  FileHandle,
				NULL, //IN HANDLE  Event  OPTIONAL,
				NULL, //IN PIO_APC_ROUTINE  ApcRoutine  OPTIONAL,
				NULL, //IN PVOID  ApcContext  OPTIONAL,
				&block, //OUT PIO_STATUS_BLOCK  IoStatusBlock,
				theLog, //IN PVOID  Buffer,
				strlen(theLog), //IN ULONG  Length,
				&AllocSize, //IN PLARGE_INTEGER  ByteOffset  OPTIONAL,
				NULL //IN PULONG  Key  OPTIONAL
			);
		InitLog();
	}
	state = ZwWriteFile(
			handle, //IN HANDLE  FileHandle,
			NULL, //IN HANDLE  Event  OPTIONAL,
			NULL, //IN PIO_APC_ROUTINE  ApcRoutine  OPTIONAL,
			NULL, //IN PVOID  ApcContext  OPTIONAL,
			&block, //OUT PIO_STATUS_BLOCK  IoStatusBlock,
			str, //IN PVOID  Buffer,
			strlen(str), //IN ULONG  Length,
			&AllocSize, //IN PLARGE_INTEGER  ByteOffset  OPTIONAL,
			NULL //IN PULONG  Key  OPTIONAL
		);
	ZwClose(handle);

}

NTSTATUS
NFilterIoControl(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )

/*++

Routine Description:

    This is the dispatch routine for Filter OID and Reset requests.

Arguments:

    DeviceObject - Pointer to the device object.

    Irp - Pointer to the request packet.

Return Value:

    Status is returned.

--*/

{
    NTSTATUS            status = STATUS_SUCCESS;

    PIO_STACK_LOCATION  irpSp;
    ULONG               functionCode;
    ULONG               dataLength =0;

	char	*pBuf = NULL;
	char		str[200];

    irpSp = IoGetCurrentIrpStackLocation(Irp);

    functionCode=irpSp->Parameters.DeviceIoControl.IoControlCode;
	switch (functionCode)
	{
	case IOCTL_FILTER_LOG_WRITE:
		WriteLog("IoCtl : Log Writing\n");
		Irp->IoStatus.Information = 0;
		break;
	case IOCTL_FILTER_SET_TEST:
		AddLog("IoCtl : Set Testing\n");
		pBuf = Irp->AssociatedIrp.SystemBuffer;
		sprintf(str, "Input Length = %d, First char = '%c'\n", 
			irpSp->Parameters.DeviceIoControl.InputBufferLength, pBuf[0]);
		AddLog(str);
		sprintf(str, "Output Length = %d\n", 
			irpSp->Parameters.DeviceIoControl.OutputBufferLength, pBuf[0]);
		strcpy(pBuf, "OK");
		Irp->IoStatus.Information = 3;
		AddLog(str);
//		strcpy(Globals.buf, irpSp->Parameters.DeviceIoControl.
		break;
	case IOCTL_FILTER_GET_TEST:
		strcpy(Irp->AssociatedIrp.SystemBuffer, "OK");
		sprintf(str, "Out Length = %d\n", 
			irpSp->Parameters.DeviceIoControl.OutputBufferLength);
		Irp->IoStatus.Information = 3;
		AddLog("IoCtl : Get Testing\n");
		AddLog(str);
		break;
	}

    Irp->IoStatus.Status = status;
    IoCompleteRequest( Irp, 0 );
    return STATUS_SUCCESS;

/*    POPEN_INSTANCE      open;
    PIO_STACK_LOCATION  irpSp;
    PINTERNAL_REQUEST   pRequest;
    ULONG               functionCode;
    NDIS_STATUS         status;
    ULONG               dataLength =0;

    DebugPrint(("IoControl\n"));
    

    //
    // Check whether this request is to get bound adapter list.
    //
    if (functionCode == IOCTL_ENUM_ADAPTERS) {
        //
        // If the request is not made to the controlobject, fail
        // the request.
        //
        if(DeviceObject != Globals.ControlDeviceObject) {
            status = STATUS_INVALID_DEVICE_REQUEST;
        } else {
            status = PacketGetAdapterList(
                            Irp->AssociatedIrp.SystemBuffer, 
                            irpSp->Parameters.DeviceIoControl.OutputBufferLength,
                            &dataLength
                            );        
        }
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = dataLength;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }

    //
    // Increment the outstanding IRP count.
    //
    open =  DeviceObject->DeviceExtension;
    IoIncrement(open);

    //
    // Check to see whether you are still bound to the adapter
    //

    if(!open->Bound)
    {
        Irp->IoStatus.Status = status = STATUS_UNSUCCESSFUL;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        IoDecrement(open);
        return status;
    }


    DebugPrint(("Function code is %08lx  buff size=%08lx  %08lx\n",
            functionCode,irpSp->Parameters.DeviceIoControl.InputBufferLength,
            irpSp->Parameters.DeviceIoControl.OutputBufferLength));

    //
    // Important: Since we have marked the IRP pending, we must return 
    // STATUS_PENDING even we happen to complete the IRP synchronously.
    // 
    
    IoMarkIrpPending(Irp);

    if (functionCode == IOCTL_PROTOCOL_RESET) {


        DebugPrint(("IoControl - Reset request\n"));

        //
        // Since NDIS doesn't have an interface to cancel a request
        // pending at miniport, we cannot set a cancel routine.
        // As a result if the application that made the request
        // terminates, we wait in the Cleanup routine for all pending
        // NDIS requests to complete.
        //
        
        ExInterlockedInsertTailList(
                &open->ResetIrpList,
                &Irp->Tail.Overlay.ListEntry,
                &open->ResetQueueLock);


        NdisReset(
            &status,
            open->AdapterHandle
            );


        if (status != NDIS_STATUS_PENDING) {

            DebugPrint(("IoControl - ResetComplete being called\n"));

            PacketResetComplete(
                open,
                status
                );

        }

    } else {
        //
        //  See if it is an Ndis request
        //
        PPACKET_OID_DATA    OidData=Irp->AssociatedIrp.SystemBuffer;

        pRequest = ExAllocatePool(NonPagedPool, sizeof(INTERNAL_REQUEST));

        if(NULL == pRequest)
        {
            Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            IoCompleteRequest (Irp, IO_NO_INCREMENT);
            IoDecrement(open);
            return STATUS_PENDING;
        }         
        pRequest->Irp=Irp;

        if (((functionCode == IOCTL_PROTOCOL_SET_OID) 
                        || (functionCode == IOCTL_PROTOCOL_QUERY_OID))
            &&
            (irpSp->Parameters.DeviceIoControl.InputBufferLength 
                        == irpSp->Parameters.DeviceIoControl.OutputBufferLength)
            &&
            (irpSp->Parameters.DeviceIoControl.InputBufferLength 
                        >= sizeof(PACKET_OID_DATA))
            &&
            (irpSp->Parameters.DeviceIoControl.InputBufferLength 
                        >= sizeof(PACKET_OID_DATA)-1+OidData->Length)) {

            DebugPrint(("IoControl: Request: Oid=%08lx, Length=%08lx\n",
                            OidData->Oid,OidData->Length));

            //
            //  The buffer is valid
            //
            if (functionCode == IOCTL_PROTOCOL_SET_OID) {

                pRequest->Request.RequestType=NdisRequestSetInformation;
                pRequest->Request.DATA.SET_INFORMATION.Oid=OidData->Oid;

                pRequest->Request.DATA.SET_INFORMATION.InformationBuffer=
                                                                OidData->Data;
                pRequest->Request.DATA.SET_INFORMATION.InformationBufferLength=
                                                           OidData->Length;


            } else {


                pRequest->Request.RequestType=NdisRequestQueryInformation;
                pRequest->Request.DATA.QUERY_INFORMATION.Oid= OidData->Oid;

                pRequest->Request.DATA.QUERY_INFORMATION.InformationBuffer=
                                        OidData->Data;
                pRequest->Request.DATA.QUERY_INFORMATION.InformationBufferLength=
                                        OidData->Length;

            }

            //
            //  submit the request
            //
            NdisRequest(
                &status,
                open->AdapterHandle,
                &pRequest->Request
                );

        } else {
            //
            //  Buffer too small. The irp is completed by
            //  PacketRequestComplete routine.
            //
            status=NDIS_STATUS_FAILURE;
            pRequest->Request.DATA.SET_INFORMATION.BytesRead=0;
            pRequest->Request.DATA.QUERY_INFORMATION.BytesWritten=0;

        }

        if (status != NDIS_STATUS_PENDING) {

            DebugPrint(("Calling RequestCompleteHandler\n"));

            PacketRequestComplete(
                open,
                &pRequest->Request,
                status
                );
                
        }

    }
*/    
}

NTSTATUS
NFilterFunc(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )

/*++

Routine Description:

    This is the dispatch routine for create/open and close requests.
    These requests complete successfully.

Arguments:

    DeviceObject - Pointer to the device object.

    Irp - Pointer to the request packet.

Return Value:

    Status is returned.

--*/

{
    NTSTATUS            status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp;

    UNREFERENCED_PARAMETER( DeviceObject );
    irpSp = IoGetCurrentIrpStackLocation( Irp );

    switch (irpSp->MajorFunction) {

        case IRP_MJ_READ:

//            KrnldrvrDump(KDVRDIAG1, ("Krnldrvr: Create\n"));
            Irp->IoStatus.Status = STATUS_SUCCESS;
            Irp->IoStatus.Information = 0L;
            break;

        case IRP_MJ_WRITE:

//            KrnldrvrDump(KDVRDIAG1, ("Krnldrvr: Close\n\n"));
            Irp->IoStatus.Status = STATUS_SUCCESS;
            Irp->IoStatus.Information = 0L;
            break;

    }

    status = Irp->IoStatus.Status;
    Irp->IoStatus.Information = 0;    
    IoCompleteRequest( Irp, 0 );
	AddLog("Net Filter Function...\n");
   return status;
}

NTSTATUS
NFilterOpen(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )

/*++

Routine Description:

    This is the dispatch routine for create/open and close requests.
    These requests complete successfully.

Arguments:

    DeviceObject - Pointer to the device object.

    Irp - Pointer to the request packet.

Return Value:

    Status is returned.

--*/

{
//    POPEN_INSTANCE      open;
    NTSTATUS            status = STATUS_SUCCESS;

	AddLog("Create Device...\n");
//    DebugPrint(("OpenAdapter\n"));

    if(DeviceObject == Globals.ControlDeviceObject) {
		Irp->IoStatus.Information = 0;    
        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }
    
//    open = DeviceObject->DeviceExtension;

/*    DebugPrint(("AdapterName :%ws\n", open->AdapterName.Buffer));

    IoIncrement(open);

    //
    // Check to see whether you are still bound to the adapter
    //

    if(!open->Bound)
    {
        status = STATUS_DEVICE_NOT_READY;
    }
*/
    Irp->IoStatus.Information = 0;    
    Irp->IoStatus.Status = status;
    IoCompleteRequest (Irp, IO_NO_INCREMENT);
//    IoDecrement(open);
    return status;
}



NTSTATUS
NFilterClose(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )

/*++

Routine Description:

    This is the dispatch routine for create/open and close requests.
    These requests complete successfully.

Arguments:

    DeviceObject - Pointer to the device object.

    Irp - Pointer to the request packet.

Return Value:

    Status is returned.

--*/

{

//    POPEN_INSTANCE      open;
    NTSTATUS            status = STATUS_SUCCESS;

 	AddLog("Close Device...\n");
//    DebugPrint(("CloseAdapter \n"));

	/*
    if(DeviceObject == Globals.ControlDeviceObject) {
		Irp->IoStatus.Information = 0;    
        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }
*/
/*    open = DeviceObject->DeviceExtension;

    IoIncrement(open);
*/
    Irp->IoStatus.Information = 0; 
    Irp->IoStatus.Status = status;
    IoCompleteRequest (Irp, IO_NO_INCREMENT);

//    IoDecrement(open);
    return status;

}

VOID
NFilterUnload(
    IN PDRIVER_OBJECT DriverObject
    )

/*++

Routine Description:

    This is the unload routine for the KRNLDRVR sample device driver.
    This routine deletes the device object and symbolic link created
    in the DriverEntry routine.

Arguments:

    DriverObject - Pointer to driver object created by the system.

Return Value:

    The function value is the final status from the initialization operation.

--*/

{
    UNICODE_STRING nameString, linkString;

	WriteLog("Device Unloading ....\n");
//    KrnldrvrDump(KDVRDIAG1, ("Krnldrvr: Unload\n"));

    IoDeleteDevice (DriverObject->DeviceObject);

    RtlInitUnicodeString( &linkString, DOS_DEVICE_NAME);//L"\\DosDevices\\KRNLDRVR" );
    RtlInitUnicodeString( &nameString, NT_DEVICE_NAME);//L"\\Device\\Krnldrvr" );

    IoDeleteSymbolicLink (&linkString);

}

NTSTATUS
DriverEntry(
	IN	PDRIVER_OBJECT		DriverObject,
	IN	PUNICODE_STRING		RegistryPath
	)
/*++

Routine Description:


Arguments:

Return Value:


--*/
{
	NDIS_STATUS						Status;
	NDIS_PROTOCOL_CHARACTERISTICS	PChars;
	NDIS_MINIPORT_CHARACTERISTICS	MChars;
	PNDIS_CONFIGURATION_PARAMETER	Param;
	NDIS_STRING						Name;
	NDIS_HANDLE						WrapperHandle;
	NDIS_HANDLE						DeviceHandle;
    UNICODE_STRING                  ntDeviceName;
    UNICODE_STRING                  win32DeviceName;
    PDEVICE_OBJECT                  deviceObject;
	NDIS_STRING						DeviceName;
	NDIS_STRING						SymbolName;
static NDIS_PHYSICAL_ADDRESS HighestAcceptableAddress = 
								NDIS_PHYSICAL_ADDRESS_CONST(-1,-1);

	ULONG	index;
	PDRIVER_DISPATCH  Funcs[IRP_MJ_MAXIMUM_FUNCTION];

	// Register the miniport with NDIS. Note that it is the miniport
	// which was started as a driver and not the protocol. Also the miniport
	// must be registered prior to the protocol since the protocol's BindAdapter
	// handler can be initiated anytime and when it is, it must be ready to
	// start driver instances.
	//
	InitLog();
	AddLog(" ==> Driver Entry\n");

	Globals.NdisDeviceHandle = NULL;

	Globals.DriverObject = DriverObject;

    //
    // Save the RegistryPath.
    //

    Globals.RegistryPath.MaximumLength = RegistryPath->Length +
                                          sizeof(UNICODE_NULL);
    Globals.RegistryPath.Length = RegistryPath->Length;
    Globals.RegistryPath.Buffer = ExAllocatePool(
                                       PagedPool,
                                       Globals.RegistryPath.MaximumLength
                                       );    

    if (!Globals.RegistryPath.Buffer) {

        WriteLog (("Couldn't allocate pool for registry path.\n"));

        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlCopyUnicodeString(&Globals.RegistryPath, RegistryPath);

	for (index=0; index<MAX_PASS_PACKET; index++)
	{
		gPackets[index].Packet = NULL;
		gPackets[index].BlockLen = BLOCK_SIZE;
		gPackets[index].Buffer = NULL;
		
		Status = NdisAllocateMemory(&(gPackets[index].Block), BLOCK_SIZE, 0, HighestAcceptableAddress);
		if (Status != NDIS_STATUS_SUCCESS)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}

	NdisMInitializeWrapper(&WrapperHandle, DriverObject, RegistryPath, NULL);

	Globals.WrapperHandle = WrapperHandle;
	
	NdisZeroMemory(&MChars, sizeof(NDIS_MINIPORT_CHARACTERISTICS));

	MChars.MajorNdisVersion = 4;
	MChars.MinorNdisVersion = 0;

	MChars.InitializeHandler = MPInitialize;
	MChars.QueryInformationHandler = MPQueryInformation;
	MChars.SetInformationHandler = MPSetInformation;
	MChars.ResetHandler = MPReset;
	MChars.TransferDataHandler = MPTransferData;
	MChars.HaltHandler = MPHalt;

	//
	// We will disable the check for hang timeout so we do not
	// need a check for hang handler!
	//
	MChars.CheckForHangHandler = NULL;
	MChars.SendHandler = MPSend;
	MChars.ReturnPacketHandler = MPReturnPacket;

	//
	// Either the Send or the SendPackets handler should be specified.
	// If SendPackets handler is specified, SendHandler is ignored
	//
	MChars.SendPacketsHandler = MPSendPackets;

	Status = NdisIMRegisterLayeredMiniport(WrapperHandle,
										   &MChars,
										   sizeof(MChars),
										   &DriverHandle);
	ASSERT(Status == NDIS_STATUS_SUCCESS);

	NdisMRegisterUnloadHandler(WrapperHandle, PtUnload);

	//
	// Now register the protocol.
	//
	NdisZeroMemory(&PChars, sizeof(NDIS_PROTOCOL_CHARACTERISTICS));
	PChars.MajorNdisVersion = 4;
	PChars.MinorNdisVersion = 0;

	//
	// Make sure the protocol-name matches the service-name under which this protocol is installed.
	// This is needed to ensure that NDIS can correctly determine the binding and call us to bind
	// to miniports below.
	//
	NdisInitUnicodeString(&Name, L"NFilter");	// Protocol name
	PChars.Name = Name;
	PChars.OpenAdapterCompleteHandler = PtOpenAdapterComplete;
	PChars.CloseAdapterCompleteHandler = PtCloseAdapterComplete;
	PChars.SendCompleteHandler = PtSendComplete;
	PChars.TransferDataCompleteHandler = PtTransferDataComplete;
	
	PChars.ResetCompleteHandler = PtResetComplete;
	PChars.RequestCompleteHandler = PtRequestComplete;
	PChars.ReceiveHandler = PtReceive;
	PChars.ReceiveCompleteHandler = PtReceiveComplete;
	PChars.StatusHandler = PtStatus;
	PChars.StatusCompleteHandler = PtStatusComplete;
	PChars.BindAdapterHandler = PtBindAdapter;
	PChars.UnbindAdapterHandler = PtUnbindAdapter;
	PChars.UnloadHandler = NULL;
	PChars.ReceivePacketHandler = PtReceivePacket;
	PChars.PnPEventHandler= PtPNPHandler;

	NdisRegisterProtocol(&Status,
						 &ProtHandle,
						 &PChars,
						 sizeof(NDIS_PROTOCOL_CHARACTERISTICS));

	ASSERT(Status == NDIS_STATUS_SUCCESS);

	NdisIMAssociateMiniport(DriverHandle, ProtHandle);

 	//////////////////////////	START  ADDED BY LC	////////////////////////
	////////	Registering Device ////////////////////////////////

	for (index = 0; index < IRP_MJ_MAXIMUM_FUNCTION; index++)
		Funcs[index] = NFilterFunc;

    Funcs[IRP_MJ_CREATE] = NFilterOpen;
    Funcs[IRP_MJ_CLOSE]  = NFilterClose;
    Funcs[IRP_MJ_DEVICE_CONTROL]  = NFilterIoControl;
    Funcs[IRP_MJ_READ]  = NFilterFunc;
    Funcs[IRP_MJ_WRITE]  = NFilterFunc;
    Funcs[IRP_MJ_CLEANUP]  = NFilterFunc;
    Funcs[IRP_MJ_FLUSH_BUFFERS]  = NFilterFunc;
    Funcs[IRP_MJ_SHUTDOWN]  = NFilterFunc;
    Funcs[IRP_MJ_INTERNAL_DEVICE_CONTROL]  = NFilterFunc;


	NdisInitUnicodeString(&DeviceName, NT_DEVICE_NAME);	// Device name
	NdisInitUnicodeString(&SymbolName, DOS_DEVICE_NAME);// Symbolic name

	Status = NdisMRegisterDevice(Globals.WrapperHandle, 
		&DeviceName, &SymbolName, 
		Funcs,
		&deviceObject,&Globals.NdisDeviceHandle);

    if (!NT_SUCCESS(Status))    // If we couldn't create the link then
    {                           //  abort installation.
		AddLog("Register Device FAILED !!\n");
    }
	else
		AddLog("Register Device OK!\n");
	///////////	Registering END		///////////////////////////////////
	
	WriteLog("<== Driver Entry\n");
	return(Status);
}

