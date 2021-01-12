/*++

Copyright (c) 1992  Microsoft Corporation

Module Name:

	miniport.c

Abstract:

	Ndis �߰� �̴���Ʈ ����̹� �Ƿ�. �̰��� passthru ����̹��Դϴ�.

Author:

Environment:


Revision History:


--*/

#include "precomp.h"
#include "passthru.h"
#include <stdio.h>
#pragma hdrstop


NDIS_STATUS
MPInitialize(
	OUT PNDIS_STATUS			OpenErrorStatus,
	OUT PUINT					SelectedMediumIndex,
	IN	PNDIS_MEDIUM			MediumArray,
	IN	UINT					MediumArraySize,
	IN	NDIS_HANDLE				MiniportAdapterHandle,
	IN	NDIS_HANDLE				WrapperConfigurationContext
	)
/*++

Routine Description:

	�̰��� NdisIMInitializeDeviceInstanceEx()�� ȣ���ϴ� BindAdapter �ڵ鷯�� ����� ȣ��Ǵ� 
	�ʱ�ȭ �ڵ鷯�Դϴ�. �츮�� �����Ű�� context �Ķ���ʹ� �츮�� ���⼭ �ٽ� ��ġ�� 
	adapter ����ü�Դϴ�. �츮�� ���� ���� ���� ������ �ʱ�ȭ�ؾ� �մϴ�.
	
	LoadBalalncing- �츮�� ��ġ�� ��� passthru �̴���Ʈ���� �뿪 ��� �� 
	���� BundleId�� ������ (������Ʈ������ �д´�)�װ͵� �Ѵ��� �ݵ� ����� �����մϴ�.

	�μ���:

	OpenErrorStatus			�츮�� ������� �ʽ��ϴ�.
	SelectedMediumIndex		�츮�� ����ϰ� �ִ� ��ü�� ���� ��ġ ������
	MediumArray				�츮���� �Ʒ� ����Ǵ� ndis ��ü�� ���
	MediumArraySize			����� ũ��
	MiniportAdapterHandle	�츮�� �����ϱ� ���� NDIS �� ����ϴ� �ڵ鷯
	WrapperConfigurationContext	NdisOpenConfiguration�� ���� ����� ���� �ʿ�

������:

	NDIS_STATUS_SUCCESS �ƹ��͵� �̻��� ������

--*/
{
	UINT	i;
	PADAPT	pAdapt;
	NDIS_STATUS						Status = NDIS_STATUS_FAILURE;


	NDIS_STATUS						BundleStatus = NDIS_STATUS_FAILURE;
	NDIS_STRING						BundleUniString;
	KIRQL							OldIrql;
	//
	// adapter ���� �˻��� �ű⿡ �ִ� �̴���Ʈ �ڵ鷯 ���忡 ���� ����
	//
	DBGPRINT("==>Passthru Initialize Miniport\n");
 	AddLog("==>Passthru Initialize Miniport\n");

	pAdapt = NdisIMGetDeviceContext(MiniportAdapterHandle);
	pAdapt->MiniportHandle = MiniportAdapterHandle;

	//
	// Make sure the medium saved is one of the ones being offered
	// ������ ��ü�� ������ �͵��� �ϳ��ΰ��� Ȯ��
	//

	for (i=0; i<MAX_PASS_PACKET; i++)
	{
		FreePassPacket(&gPackets[i]);
	}
	
	for (i = 0; i < MediumArraySize; i++)
	{
		if (MediumArray[i] == pAdapt->Medium)
		{
			*SelectedMediumIndex = i;
			break;
		}
	}

	if (i == MediumArraySize)
	{
		return(NDIS_STATUS_UNSUPPORTED_MEDIA);
	}


	//
	// Set the attributes now. The NDIS_ATTRIBUTE_DESERIALIZE is the key. This enables us
	// to make up-calls to NDIS w/o having to call NdisIMSwitchToMiniport/NdisIMQueueCallBack.
	// This also forces us to protect our data using spinlocks where appropriate. Also in this
	// case NDIS does not queue packets on out behalf. Since this is a very simple pass-thru
	// miniport, we do not have a need to protect anything. However in a general case there
	// will be a need to use per-adapter spin-locks for the packet queues at the very least.

	// ���� �Ӽ� ����. NDIS_ATTRIBUTE_DESERIALIZE �� Ű�̴�. �̰��� �츮�� �Ͽ��� NDIS w/o�� 
	// NdisIMSwitchToMiniport/NdisIMQueueCallBack�� ȣ���ϵ��� ȣ���� ����� �մϴ�.
	// �̰��� ���� �츮�� spinlocks�� ������ ����Ͽ� �츮�� �ڷḦ ��ȣ�ϵ��� �䱸�մϴ�.
	// ���� �̰�쿡 NDIS�� �ك� ���鿡�� ����Ʈ���� ����Ű�� �ʽ��ϴ�. �̰��� �ſ� ������ 
	// pass-thru �̴���Ʈ�̱⶧���� �츮�� �ƹ��͵� ��ȣ�� �ʿ䰡 �����ϴ�. �׷��� �Ϲ� ��쿡
	// ���� �ּ��� ����Ʈ�� ����ϴµ� ���� �ƴ��͸� ���� spin-locks�� ����ؾ� �Ұ��Դϴ�.
	//
	NdisMSetAttributesEx(MiniportAdapterHandle,
						 pAdapt,
						 0,										// CheckForHangTimeInSeconds
						 NDIS_ATTRIBUTE_IGNORE_PACKET_TIMEOUT	|
							NDIS_ATTRIBUTE_IGNORE_REQUEST_TIMEOUT|
							NDIS_ATTRIBUTE_INTERMEDIATE_DRIVER |
							NDIS_ATTRIBUTE_DESERIALIZE |
							NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND,
						 0);

	//
	// Setting up the default value for the Device State Flag as PM capable
	// initialize the PM Variable, (for both miniport and the protocol) Device is ON by default
	// ��ġ ���¿� ���� ������ ����. PM�� PM ������ �ʱ�ȭ�Ҽ� �ְ� (�̴���Ʈ�� �������� �Ѵ�)
	// ��ġ�� �������� ON
	//
	pAdapt->MPDeviceState=NdisDeviceStateD0;
	pAdapt->PTDeviceState=NdisDeviceStateD0;

	//
	// Begin the Load Balancing and Bundle Identifier work here
	// Default case: the miniport is the primary miniport
	// ���� ���߱�� �ݵ� �ĺ��� ���� �۾��� ���⼭ ����
	// ���� ���: �̴���Ʈ�� ���� �̴���Ʈ
	//
	pAdapt->isSecondary		=	FALSE;	// ���� - ����
	pAdapt->pPrimaryAdapt	=	pAdapt;	//����, ��ü�� ����
	pAdapt->pSecondaryAdapt	=	pAdapt;	//����, ��ü�� ����

	//
	// Set miniport as a secondary miniport, if need be
	// �ʿ��ϸ� �̴���Ʈ�� ���� �̴���Ʈ�� ����
	//
	BundleStatus  =	MPBundleSearchAndSetSecondary (pAdapt);

	//
	// Inserting into our global Passthru pAdapt List
	// �츮�� �뿪 Passthru pAdapt ��Ͽ� �߰�
	//
	KeAcquireSpinLock (&pAdapt->SpinLock, &OldIrql);

	pAdapt->Next = pAdaptList;
	pAdaptList = pAdapt;

	KeReleaseSpinLock (&pAdapt->SpinLock, OldIrql);
		
	//
	// We are done, In current implementation, Bundle Status does not affect the success of initialization
	// ��. ���� ���࿡�� �ݵ� ���´� �ʱ�ȭ�� ������ ������ �����ʴ´�
	//
	Status = NDIS_STATUS_SUCCESS;

	DBGPRINT(" Passthru Initialize Miniport\n");
 	AddLog("<==Passthru Initialize Miniport\n");

	return Status;
}

VOID AdjustPacket(PPASS_PACKET packet)
{
	PNDIS_BUFFER ndisBuffer=NULL;

	NdisUnchainBufferAtFront(packet->Packet, &ndisBuffer);
	NdisAdjustBufferLength(ndisBuffer, packet->BlockLen);
	NdisChainBufferAtFront(packet->Packet, ndisBuffer);
}

PPASS_PACKET FindPacketFromOrgPacket(PNDIS_PACKET pPacket)
{
	int		i;
	for (i=0; i<MAX_PASS_PACKET; i++)
	{
		if (gPackets[i].Packet == pPacket)
			return &gPackets[i];
	}
	return NULL;
}

PPASS_PACKET FindUnusedPacket()
{
	return FindPacketFromOrgPacket(NULL);
}

int 
AllocPacketFromPacket(
	IN PPASS_PACKET pPassPacket,
	IN PNDIS_PACKET srcPacket,
	IN	UINT Flags,
	OUT PADAPT pAdapt)
{
	NDIS_STATUS		Status;
	PRSVD			Rsvd;
	PVOID			MediaSpecificInfo = NULL;
	ULONG			MediaSpecificInfoSize = 0;
	char			str[200];
	unsigned char *pBuf;
	PNDIS_PACKET_OOB_DATA	pOOB;
	int		block_size = BLOCK_SIZE;
	PNDIS_BUFFER ndisBuffer;

	UINT			numNdisBuffer;
	PNDIS_BUFFER	CurrentBuffer;
	PVOID			CurrentBlock;
	UINT			CurrentLength;
	UINT			BytesCopied;

	AddLog("Alloc Packet\n");
	NdisAllocatePacket(&Status,
					   &pPassPacket->Packet,
					   pAdapt->SendPacketPoolHandle);

	if (Status == NDIS_STATUS_SUCCESS)
	{
		Rsvd = (PRSVD)(pPassPacket->Packet->ProtocolReserved);
		NdisAllocateBuffer(&Status, &pPassPacket->Buffer, 
			pAdapt->SendPacketPoolHandle, pPassPacket->Block, BLOCK_SIZE);
		
		CopyPacketToBlock(srcPacket, pPassPacket->Block, &pPassPacket->BlockLen);
		NdisAdjustBufferLength(pPassPacket->Buffer, pPassPacket->BlockLen);
		NdisChainBufferAtFront(pPassPacket->Packet, pPassPacket->Buffer);

		Rsvd->OriginalPkt = srcPacket;
		NdisSetPacketFlags(pPassPacket->Packet, NDIS_FLAGS_DONT_LOOPBACK);
	
		pPassPacket->Packet->Private.Count = 1;
		pPassPacket->Packet->Private.Flags = 0;
		pPassPacket->Packet->Private.NdisPacketFlags = 0xB0;
		pPassPacket->Packet->Private.PhysicalCount = 1;
		pPassPacket->Packet->Private.TotalLength = pPassPacket->BlockLen;
		pPassPacket->Packet->Private.ValidCounts = 1;
		pPassPacket->Packet->Private.Head = pPassPacket->Buffer;
		pPassPacket->Packet->Private.Tail = pPassPacket->Buffer;

		//
		// Copy the OOB Offset from the original packet to the new
		// packet.
		// ���ο� ����Ʈ�� ���� ����Ʈ�� OOB ������ ����.
		//

		NdisMoveMemory(NDIS_OOB_DATA_FROM_PACKET(pPassPacket->Packet),
					   NDIS_OOB_DATA_FROM_PACKET(srcPacket),
					   sizeof(NDIS_PACKET_OOB_DATA));


		//
		// Copy the per packet info into the new packet
		// This includes ClassificationHandle, etc.
		// Make sure other stuff is not copied !!!
		// ���ο� ����Ʈ�� ����Ʈ ������ ����
		// �̰��� ClassificationHandle, ���� �����Ѵ�.
		// �ٸ� stuff�� ������� �ʴ��� Ȯ�� !!!
		//

		NdisIMCopySendPerPacketInfo(pPassPacket->Packet, srcPacket);
		
		//
		// Copy the Media specific information
		// ��ü Ư�� ���� ����
		//
		NDIS_GET_PACKET_MEDIA_SPECIFIC_INFO(srcPacket,
											&MediaSpecificInfo,
											&MediaSpecificInfoSize);

		if (MediaSpecificInfo || MediaSpecificInfoSize)
		{
			NDIS_SET_PACKET_MEDIA_SPECIFIC_INFO(pPassPacket->Packet,
												MediaSpecificInfo,
												MediaSpecificInfoSize);
		}
	}
	else
		return -1;
	return 	0;
}

VOID 
FreePassPacket(IN PPASS_PACKET pPassPacket)
{
	NDIS_STATUS		Status;
	PNDIS_BUFFER buffer = NULL;

	AddLog("Free Packet\n");
	if (pPassPacket->Packet)
	{
		NdisUnchainBufferAtFront(pPassPacket->Packet, &buffer);

		if (buffer)
		{
			//NdisFreeBuffer(packet->xformBuffer); //?
			NdisFreeBuffer(buffer);
		}
		pPassPacket->Buffer = NULL;
		NdisFreePacket(pPassPacket->Packet);
		pPassPacket->Packet = (PNDIS_PACKET)NULL;
	}
}

VOID CopyPacketToBlock(
		IN PNDIS_PACKET	packet,
		IN PUCHAR			block,
		OUT PUINT			BytesCopied)
{

	UINT			numNdisBuffer;
	PNDIS_BUFFER	CurrentBuffer;
	PVOID			CurrentBlock;
	UINT			CurrentLength;

	unsigned char *pBuf;
	char		str[200];

	*BytesCopied = 0;
	NdisQueryPacket(packet, NULL, &numNdisBuffer, &CurrentBuffer, NULL);

	if (numNdisBuffer == 0)
		return;

	NdisQueryBuffer(CurrentBuffer, &CurrentBlock, &CurrentLength);

	while(CurrentBuffer != NULL)
	{
		pBuf = (unsigned char*)CurrentBlock;
		NdisMoveMemory(block, CurrentBlock, CurrentLength);
		block = (PUCHAR)block + CurrentLength;
		*BytesCopied = *BytesCopied + CurrentLength;


		NdisGetNextBuffer(CurrentBuffer, &CurrentBuffer);
		if (CurrentBuffer == NULL)
			break;
		NdisQueryBuffer(CurrentBuffer, &CurrentBlock, &CurrentLength);
	}
}

NDIS_STATUS
MPSend(
	IN	NDIS_HANDLE				MiniportAdapterContext,
	IN	PNDIS_PACKET			Packet,
	IN	UINT					Flags
	)
/*++

Routine Description:

	Send handler. Just re-wrap the packet and send it below. Re-wrapping is necessary since
	NDIS uses the WrapperReserved for its own use.

	�۽� �ڵ鷯. ���⼭ ����Ʈ�� �������ϰ� �װ��� �Ʒ��� �۽��մϴ�. �� ������ NDIS�� 
	���� ��ü ����� ���� WrapperReserved�� ����Ҷ� �ʿ��մϴ�.
	
	LBFO- All sends will be done in the secondary miniport of the bundle.
	LBFO- ��� �۽ŵ��� �ݵ��� ���� �̴���Ʈ���� �������Դϴ�.

	We are using the Secondary Miniport as the Send path. All sends should use that pAdapt structure.
	�츮�� ���� �̴���Ʈ�� �۽� ��η� ����ϰ� �ֽ��ϴ�.
	��� �۽ŵ��� �ش� pAdapt ����ü�� ����ؾ� �մϴ�.

Arguments:

	MiniportAdapterContext	�ƴ��Ϳ��ΐl ���ñ�
	Packet					�۽��Ϸ��� ����Ʈ
	Flags					������ ����, �Ʒ��� �����

Return Value:

	Return code from NdisSend
	NdisSend�κ��� �� �ڵ带 ����

--*/
{
	PADAPT			pAdapt = (PADAPT)MiniportAdapterContext;
	NDIS_STATUS		Status = NDIS_STATUS_SUCCESS;
//	PNDIS_PACKET	MyPacket;
	PRSVD			Rsvd;
	PVOID			MediaSpecificInfo = NULL;
	ULONG			MediaSpecificInfoSize = 0;
	char			str[200];
	PNDIS_PACKET_OOB_DATA	pOOB;
	PNDIS_BUFFER	src_buffer;
	UINT			src_len;
	PNDIS_BUFFER	working_buffer;
	PVOID			working_block;
	UINT			working_block_len;
	unsigned char *pBuf;
	PNDIS_BUFFER ndisBuffer;
	PASS_PACKET		PassPacket;
	
	UINT			numNdisBuffer;
	PNDIS_BUFFER	CurrentBuffer;
	PVOID			CurrentBlock;
	UINT			CurrentLength;
	UINT			BytesCopied;
	//
	//  According to our LBFO design, all sends will be performed on the secondary miniport
	//	However, the must be completed on the primary's miniport handle
	//  �츮�� LBFO ���迡 ���ϸ� ��� �۽ŵ��� ���� �̴���Ʈ���� ����ɰ��Դϴ�.
	//	�׷��� ���� �̴���Ʈ �ڵ鿡�� �Ϸ�ǿ��� �մϴ�.
	//

	AddLog("MPSend  : ");
	ASSERT (pAdapt->pSecondaryAdapt);

	pAdapt = pAdapt->pSecondaryAdapt;


	if (IsIMDeviceStateOn (pAdapt) == FALSE)
	{
		return NDIS_STATUS_FAILURE;
	}

	if(AllocPacketFromPacket(&PassPacket,Packet,Flags,pAdapt)!=0)
	{
		return NDIS_STATUS_FAILURE;
	}
	if (Status == NDIS_STATUS_SUCCESS)
	{
//		PassPacket.Block[6] = 0x00;
//		PassPacket.Block[7] = 0x01;
//		PassPacket.Block[8] = 0x02;
//		PassPacket.Block[9] = 0x78;
//		PassPacket.Block[10] = 0x03;
//		PassPacket.Block[11] = 0x08;

		NdisSend(&Status,
				 pAdapt->BindingHandle,
				 PassPacket.Packet);

		if (Status != NDIS_STATUS_PENDING)
		{
			NdisIMCopySendCompletePerPacketInfo (Packet, PassPacket.Packet);
			FreePassPacket(&PassPacket);
			//NdisFreePacket(MyPacket);
		}

	}
	else
	{
		//
		// We are out of packets. Silently drop it. Alternatively we can deal with it:
		//	- By keeping separate send and receive pools
		//	- Dynamically allocate more pools as needed and free them when not needed
		//
	}

	return(Status);
}


VOID
MPSendPackets(
	IN	NDIS_HANDLE				MiniportAdapterContext,
	IN	PPNDIS_PACKET			PacketArray,
	IN	UINT					NumberOfPackets
	)
/*++

Routine Description:

	Batched send-handler. TBD. Either this or the Send function can be specified but not both.
	LBFO - The Send will be done on the secondary miniport of the bundle

Arguments:

	MiniportAdapterContext	Pointer to our adapter
	PacketArray				Set of packets to send
	NumberOfPackets			Self-explanatory

Return Value:

	None

--*/
{
	PADAPT			pAdapt = (PADAPT)MiniportAdapterContext;
	NDIS_STATUS		Status;
	UINT			i;
	PVOID			MediaSpecificInfo = NULL;
	UINT			MediaSpecificInfoSize = 0;
	PPASS_PACKET		pPassPacket;

	char			str[200];
	//
	//	Route all sends to the seondary, if no secondary exists, it will point to itself
	//
	pAdapt = pAdapt->pSecondaryAdapt;

	sprintf(str, "Send %d Packets :", NumberOfPackets);
	AddLog(str);
	for (i = 0; i < NumberOfPackets; i++)
	{
		PRSVD			Rsvd;
		PNDIS_PACKET	Packet;

		Packet = PacketArray[i];

		if (IsIMDeviceStateOn(pAdapt) == FALSE)
		{
			Status = NDIS_STATUS_FAILURE;
			break;
		}

		pPassPacket = FindUnusedPacket();

		if (pPassPacket == NULL)
		{
			Status = NDIS_STATUS_FAILURE;
			break;
		}
		if(AllocPacketFromPacket(pPassPacket,Packet,0,pAdapt)!=0)
		{
			Status = NDIS_STATUS_FAILURE;
			break;
		}

		NdisSend(&Status,
				 pAdapt->BindingHandle,
				 pPassPacket->Packet);

		if (Status != NDIS_STATUS_PENDING)
		{
			AddLog("NO PENDING...\n");
			NdisIMCopySendCompletePerPacketInfo (Packet, pPassPacket->Packet);
			FreePassPacket(pPassPacket);
		}
		else
			AddLog("PENDING...\n");

		if (Status != NDIS_STATUS_PENDING)
		{
			//
			// We are out of packets. Silently drop it. Alternatively we can deal with it:
			//	- By keeping separate send and receive pools
			//	- Dynamically allocate more pools as needed and free them when not needed
			//
			NdisMSendComplete(pAdapt->pPrimaryAdapt->MiniportHandle,
							  Packet,
							  Status);

			// LBFO - Complete with the prmary's miniport handle
			// We should use the miniport handle that was used to call this function
		}
	}
	AddLog("Send Packets OK\n");
}


NDIS_STATUS
MPQueryInformation(
	IN	NDIS_HANDLE				MiniportAdapterContext,
	IN	NDIS_OID				Oid,
	IN	PVOID					InformationBuffer,
	IN	ULONG					InformationBufferLength,
	OUT PULONG					BytesWritten,
	OUT PULONG					BytesNeeded
		)
/*++

Routine Description:

	Miniport QueryInfo handler.
	In the Power Management scenario, OID_PNP_QUERY_POWER is not sent to the underlying miniport.
	OID_PNP_CAPABILITES is passed as a request to the miniport below.
	If the result is a success then the InformationBuffer is filled in the MPQueryPNPCapabilites.
	�̴���Ʈ QueryInfo �ڵ鷯.
	���� ���� �ó��������� OID_PNP_QUERY_POWER �� ���� �̴���Ʈ�� �������� �ʽ��ϴ�.
	OID_PNP_CAPABILITES �� �̴���Ʈ �Ʒ��� ��û���� ����˴ϴ�.
	����� �����̸� InformationBuffer�� the MPQueryPNPCapabilites���� ä�����ϴ�.

	LBFO - For present all queries are passed on to the miniports that they were requested on.
	LBFO - ���� ��� ���ǵ��� �װ͵��� ��û�� �̴���Ʈ�鿡�� ����˴ϴ�.

	PM- If the MP is not ON (DeviceState > D0) return immediately  (except for query power and set power)
         If MP is ON, but the PT is not at D0, then queue the queue the request for later processing
	PM- MP �� ON �̾ƴϸ� (DeviceState > D0) ���� ���� (���� ���ǿ� ���� ������ ������)
         MP �� ON ������ PT �� D0 �� ���� ������ ������ ó���� ���� ��û�� ���Ŀ� ����Ѵ�.

	Requests to miniports are always serialized
	�̴���Ʈ�鿡���� ��û���� �̹� ����ȭ�ǿ���.

Arguments:

	MiniportAdapterContext	�ƴ��� ����ü������ ���ñ�
	Oid						�� ���ǿ� ���� Oid
	InformationBuffer		���� �����
	InformationBufferLength	�� ������� ũ��
	BytesWritten			�󸶳� ���� ������ �ۼ��ǿ����� ����
	BytesNeeded				In case the buffer is smaller than what we need, tell them how much is needed
							����Ⱑ �ʿ��Ѱͺ��� ������� �󸶳� �ʿ����� �˸���


Return Value:

	Return code from the NdisRequest below.
	NdisRequest �κ��� �� �ڵ带 �Ʒ��� �����Ѵ�.

--*/
{
	PADAPT	pAdapt = (PADAPT)MiniportAdapterContext;
	NDIS_STATUS	Status = NDIS_STATUS_FAILURE;

	do
	{
		//
		// Return Success for this OID
		// �� OID�� ���� ������ ����
		//
		if (Oid == OID_PNP_QUERY_POWER)
		{
			Status=NDIS_STATUS_SUCCESS;
			break;
		}

		//
		// All other queries are failed, if the miniport is not at D0
		// ���� �̴���Ʈ�� D0�� �ƴϸ� ��� �ٸ� ��û���� ����
		//
		if (pAdapt->MPDeviceState > NdisDeviceStateD0 || pAdapt->StandingBy == TRUE)
		{
			Status = NDIS_STATUS_FAILURE;
			break;
		}
		//
		//	We are doing all sends on the secondary, so send all requests with Send OIDs to the Secondary
		//	�츮�� �������� ��� �۽ŵ��� �����Ͽ� �������� �۽� OID���� ���� ��� ��û���� �۽��Ͽ���.
		//
		if (MPIsSendOID(Oid))
		{
			pAdapt = pAdapt->pSecondaryAdapt;
			//
			// Will point to itself, if there is no secondary (see initialization)
			// ���� ������ ������ �� ��ü�� ����ų���̴�.(�ʱ�ȭ�� ����)
			//
		}

		pAdapt->Request.RequestType = NdisRequestQueryInformation;
		pAdapt->Request.DATA.QUERY_INFORMATION.Oid = Oid;
		pAdapt->Request.DATA.QUERY_INFORMATION.InformationBuffer = InformationBuffer;
		pAdapt->Request.DATA.QUERY_INFORMATION.InformationBufferLength = InformationBufferLength;
		pAdapt->BytesNeeded = BytesNeeded;
		pAdapt->BytesReadOrWritten = BytesWritten;
		pAdapt->OutstandingRequests = TRUE;

		//
		// if the Protocol device state is OFF, then the IM driver cannot send the request below and must pend it
		// �������� ��ġ ���°� OFF�̸� IM ����̹��� ��û���� �Ʒ��� �۽��Ҽ� ������ �װ��� �̰�� ���ܾ� �Ѵ�.
		//
		if (pAdapt->PTDeviceState > NdisDeviceStateD0)
		{
			pAdapt->QueuedRequest = TRUE;
			Status = NDIS_STATUS_PENDING;
			break;
		}

		//
		// default case, most requests will be passed to the miniport below
		// ���� ��� ��κ��� ��û���� �̴���Ʈ �Ʒ��� ����ɰ��̴�
		//
		NdisRequest(&Status,
					pAdapt->BindingHandle,
					&pAdapt->Request);


		//
		// If the Query was a success, pass the results back to the entity that made the request
		// ���ǰ� �����ϸ� ��û�� ����� ��ƼƼ���� ����� �Ųٷ� ������.
		//
		if (Status == NDIS_STATUS_SUCCESS)
		{
			*BytesWritten = pAdapt->Request.DATA.QUERY_INFORMATION.BytesWritten;
			*BytesNeeded = pAdapt->Request.DATA.QUERY_INFORMATION.BytesNeeded;
		}

		//
		// Fill the buffer with the required values if Oid == OID_PNP_CAPABILITIES
		// and the query was successful
		// Oid == OID_PNP_CAPABILITIES�̰� ���ǰ� �����ϸ� ��û�� ������ ����⸦ ä���
		//
		if (Oid  == OID_PNP_CAPABILITIES  && Status == NDIS_STATUS_SUCCESS)
		{
			MPQueryPNPCapbilities(pAdapt,&Status);
		}

		if (Status != NDIS_STATUS_PENDING)
		{
			pAdapt->OutstandingRequests = FALSE;
		}

	} while (FALSE);

	return(Status);

}


VOID
MPQueryPNPCapbilities(
	IN OUT	PADAPT			pAdapt,
	OUT		PNDIS_STATUS	pStatus
	)
/*++

Routine Description:

	Miniport QueryInfo OID_PNP_CAPAIBILITIES:
	If the Oid == Oid_PNP_CAPABILITIES, InformationBuffer is returned with all the fields
	assigned NdisDeviceStateUnspecified in the NDIS_PM_WAKE_UP_CAPABILITIES structure
	Oid == Oid_PNP_CAPABILITIES�̸� InformationBuffer �� NDIS_PM_WAKE_UP_CAPABILITIES ����ü��
	��� ������� NdisDeviceStateUnspecified �� �Ҵ��Ͽ� ���ϵ˴ϴ�.

	OID_QUERY_POWER_STATE is returned with NDIS_STATUS_SUCCESS and should never be passed below.
	OID_QUERY_POWER_STATE �� NDIS_STATUS_SUCCESS �� ���ϵǸ� �Ʒ��� ������� ���ƾ� �մϴ�.

Arguments:

	MiniportAdapterContext	�ƴ��� ����ü������ ���ñ�
	Oid						�� ���ǿ� ���� Oid
	InformationBuffer		���� �����
	InformationBufferLength	�� ������� ũ��
	BytesWritten			�󸶳� ���� ������ �ۼ��ǿ����� ����
	BytesNeeded				In case the buffer is smaller than what we need, tell them how much is needed
							����Ⱑ �ʿ��Ѷ����� ������ �󸶳� �ʿ����� �˸���

Return Value:

	Return code from the NdisRequest below.

--*/

{
	PNDIS_PNP_CAPABILITIES			pPNPCapabilities;
	PNDIS_PM_WAKE_UP_CAPABILITIES	pPMstruct;

	if (pAdapt->Request.DATA.QUERY_INFORMATION.InformationBufferLength >= sizeof(NDIS_PNP_CAPABILITIES))
	{
		pPNPCapabilities = (PNDIS_PNP_CAPABILITIES)(pAdapt->Request.DATA.QUERY_INFORMATION.InformationBuffer);

		//
		// Setting up the buffer to be returned to the Protocol above the Passthru miniport
		// Passthru �̴���Ʈ ������ �������ݿ� ���ϵǴ� ����⸦ �����Ѵ�.
		//
		pPMstruct= & pPNPCapabilities->WakeUpCapabilities;
		pPMstruct->MinMagicPacketWakeUp = NdisDeviceStateUnspecified;
		pPMstruct->MinPatternWakeUp = NdisDeviceStateUnspecified;
		pPMstruct->MinLinkChangeWakeUp = NdisDeviceStateUnspecified;
		*pAdapt->BytesReadOrWritten = sizeof(NDIS_PNP_CAPABILITIES);
		*pAdapt->BytesNeeded = 0;


		//
		// Setting our internal flags
		// Default, device is ON
		// �츮�� ���� ��ߵ��� ����
		// �������� ��ġ�� ON
		//
		pAdapt->MPDeviceState = NdisDeviceStateD0;
		pAdapt->PTDeviceState = NdisDeviceStateD0;

		*pStatus = NDIS_STATUS_SUCCESS;
	}
	else
	{
		*pAdapt->BytesNeeded= sizeof(NDIS_PNP_CAPABILITIES);
		*pStatus = NDIS_STATUS_RESOURCES;
	}
}


NDIS_STATUS
MPSetInformation(
	IN	NDIS_HANDLE				MiniportAdapterContext,
	IN	NDIS_OID				Oid,
	IN	PVOID					InformationBuffer,
	IN	ULONG					InformationBufferLength,
	OUT PULONG					BytesRead,
	OUT PULONG					BytesNeeded
	)
/*++

Routine Description:

	�̴���Ʈ SetInfo �ڵ鷯.

	In the case of OID_PNP_SET_POWER, record the power state and return the OID.	
	Do not pass below
	If the device is suspended, do not block the SET_POWER_OID 
	as it is used to reactivate the Passthru miniport
	OID_PNP_SET_POWER�� ��� ���� ���¸� ����ϰ� OID�� �����Ѵ�.
	�Ʒ��� �����Ű�� ����
	��ġ�� �Ŵ޷� ������ Passthru �̴���Ʈ�� ��Ȱ��ȭ �ϴµ� ���ǵ��� 
	SET_POWER_OID�� �������� ���ʽÿ�.

	
	PM- If the MP is not ON (DeviceState > D0) return immediately  (except for 'query power' and 'set power')
         If MP is ON, but the PT is not at D0, then queue the queue the request for later processing
	PM- MP �� ON�� �ƴϸ� (DeviceState > D0) ���� ����('query power' �� 'set power'�� ���ؼ��� ����)
         MP �� ON������ PT �� D0�� �ƴϸ� ������ ó���� ���� ��û�� ���Ŀ� ���

	Requests to miniports are always serialized


Arguments:

	MiniportAdapterContext	Pointer to the adapter structure
	Oid						Oid for this query
	InformationBuffer		Buffer for information
	InformationBufferLength	Size of this buffer
	BytesRead				Specifies how much info is read
	BytesNeeded				In case the buffer is smaller than what we need, tell them how much is needed

Return Value:

	Return code from the NdisRequest below.

--*/
{
	PADAPT		pAdapt = (PADAPT)MiniportAdapterContext;
	NDIS_STATUS	Status;

	Status = NDIS_STATUS_FAILURE;

	do
	{
		//
		// The Set Power should not be sent to the miniport below the Passthru, but is handled internally
		// ���� ������ Passthru �Ʒ��� �̴���Ʈ�� �۽ŵ��� ���ƾ� ������ �������� �����ȴ�
		//
		if (Oid == OID_PNP_SET_POWER)
		{
			MPProcessSetPowerOid( &Status, 
			                       pAdapt, 
			                       InformationBuffer, 
			                       InformationBufferLength, 
			                       BytesRead, 
			                       BytesNeeded);
			break;

		}

		//
		// All other Set Information requests are failed, if the miniport is not at D0 or is transitioning to
		// a device state greater than D0
		// �̴���Ʈ�� D0�� �ƴϰų� ��ġ ���°� D0���� ũ�� ����Ǹ� ��� �ٸ� ���� ���� ��û���� ���еȴ�.
		//
		if (pAdapt->MPDeviceState > NdisDeviceStateD0 || pAdapt->StandingBy == TRUE)
		{
			Status = NDIS_STATUS_FAILURE;
			break;
		}


		// Set up the Request and return the result
		// ��û�� �����ϰ� ����� ����
		pAdapt->Request.RequestType = NdisRequestSetInformation;
		pAdapt->Request.DATA.SET_INFORMATION.Oid = Oid;
		pAdapt->Request.DATA.SET_INFORMATION.InformationBuffer = InformationBuffer;
		pAdapt->Request.DATA.SET_INFORMATION.InformationBufferLength = InformationBufferLength;
		pAdapt->BytesNeeded = BytesNeeded;
		pAdapt->BytesReadOrWritten = BytesRead;
		pAdapt->OutstandingRequests = TRUE;


		//
		// if the Protocol device state is OFF, then the IM driver cannot send the request below and must pend it
		// �������� ��ġ ���°� OFF�̸� IM ����̹��� ��û�� �Ʒ��� �۽��Ҽ� ������ �װ��� �̰�� ���ܾ� �Ѵ�.
		//
		if ( pAdapt->PTDeviceState > NdisDeviceStateD0)
		{
			pAdapt->QueuedRequest = TRUE;
			Status = NDIS_STATUS_PENDING;
			break;
		}

		NdisRequest(&Status,
					pAdapt->BindingHandle,
					&pAdapt->Request);


		if (Status == NDIS_STATUS_SUCCESS)
		{
			*BytesRead = pAdapt->Request.DATA.SET_INFORMATION.BytesRead;
			*BytesNeeded = pAdapt->Request.DATA.SET_INFORMATION.BytesNeeded;
		}


		if (Status != NDIS_STATUS_PENDING)
		{
			pAdapt->OutstandingRequests = FALSE;
		}

	} while (FALSE);

	return(Status);
}


VOID
MPProcessSetPowerOid(
	IN OUT PNDIS_STATUS      pNdisStatus,
	IN  PADAPT					pAdapt,
	IN	PVOID					InformationBuffer,
	IN	ULONG					InformationBufferLength,
	OUT PULONG					BytesRead,
	OUT PULONG					BytesNeeded
    )
/*++

Routine Description:
	This routine does all the procssing for a request with a SetPower Oid
    The SampleIM miniport shoud accept  the Set Power and transition to the new state
	�� ��ƾ�� SetPower Oid�� ���� ��û�� ���� ��� ó���� �����մϴ�.
    SampleIM �̴���Ʈ�� ���� ������ �����ϰ� ���ο� ���·� �����ؾ� �մϴ�.

    The Set Power should not be passed to the miniport below
    ���� ������ �̴���Ʈ �Ʒ��� ������� ���ƾ� �մϴ�.

    If the IM miniport is going into a low power state, then there is no guarantee if it will ever
    be asked go back to D0, before getting halted. No requests should be pended or queued.
    ���� IM �̴���Ʈ�� ���� ���� ���·� ���� �����Ǳ� ���� D0���� ���ư����� 
	�׻� ������̶�� �㺸�� �����ϴ�. �̰�� �ǰų� ���ǿ��� �ϴ� ��û���� �����ϴ�.

	
Arguments:
	IN OUT PNDIS_STATUS      *pNdisStatus - ������ ����
	IN  PADAPT					pAdapt,   - �ƴ��� ����ü 
	IN	PVOID					InformationBuffer, - ���ο� ��ġ ���� 
	IN	ULONG					InformationBufferLength,
	OUT PULONG					BytesRead, - ���� ����Ʈ �� 
	OUT PULONG					BytesNeeded -  �ʿ��� ����Ʈ �� 


Return Value:
    Status  - ��� ��� ��ǵ��� �����ϸ� NDIS_STATUS_SUCCESS
    

--*/

{

	
	NDIS_DEVICE_POWER_STATE NewDeviceState;

	DBGPRINT ("==>MPProcessSetPowerOid"); 
	ASSERT (InformationBuffer != NULL);

	NewDeviceState = (*(PNDIS_DEVICE_POWER_STATE)InformationBuffer);

	*pNdisStatus = NDIS_STATUS_FAILURE;

	do 
	{
		//
		// Check for invalid length
		// ��ȿ�� ���� �˻� 
		//
		if (InformationBufferLength < sizeof(NDIS_DEVICE_POWER_STATE))
		{
			*pNdisStatus = NDIS_STATUS_INVALID_LENGTH;
			break;
		}

		//
		// Check for invalid device state
		// ��ȿ�� ��ġ ���� �˻�
		//
		if ((pAdapt->MPDeviceState > NdisDeviceStateD0) && (NewDeviceState != NdisDeviceStateD0))
		{
			//
			// If the miniport is in a non-D0 state, the miniport can only receive a Set Power to D0
			// �̴���Ʈ�� D0 ���°� �ƴϸ� �̴���Ʈ�� ������ D0���� ������ �����Ҽ��� �ֽ��ϴ�.
			//
			ASSERT (!(pAdapt->MPDeviceState > NdisDeviceStateD0) && (NewDeviceState != NdisDeviceStateD0));

			*pNdisStatus = NDIS_STATUS_FAILURE;
			break;
		}	

		//
		// Is the miniport transitioning from an On (D0) state to an Low Power State (>D0)
		// If so, then set the StandingBy Flag - (Block all incoming requests)
		// �̴���Ʈ�� On (D0) ���·κ��� ���� ���� ���� (>D0)�� ��ȯ�Ǵ°�?
		// �׷��ٸ� StandingBy ����� ���� (������ ��û���� ��� ����)
		//
		if (pAdapt->MPDeviceState == NdisDeviceStateD0 && NewDeviceState > NdisDeviceStateD0)
		{
			pAdapt->StandingBy = TRUE;
		}

		//
		// If the miniport is transitioning from a low power state to ON (D0), then clear the StandingBy flag
		// All incoming requests will be pended until the physical miniport turns ON.
		// �̴���Ʈ�� ���� ���� ���·κ��� ON (D0)���� ��ȯ�Ǹ� StandingBy ����� ����
		// ������ ��� ��û���� ���� �̴���Ʈ�� ON���� �ɶ����� �̰�� �ɰ��Դϴ�.
		//
		if (pAdapt->MPDeviceState > NdisDeviceStateD0 &&  NewDeviceState == NdisDeviceStateD0)
		{
			pAdapt->StandingBy = FALSE;
		}
		
		//
		// Now update the state in the pAdapt structure;
		// pAdapt ����ü�� ���¸� ����;
		//
		pAdapt->MPDeviceState = NewDeviceState;
		
		*pNdisStatus = NDIS_STATUS_SUCCESS;
	

	} while (FALSE);	
		
	if (*pNdisStatus == NDIS_STATUS_SUCCESS)
	{
		*BytesRead = sizeof(NDIS_DEVICE_POWER_STATE);
		*BytesNeeded = 0;
	}
	else
	{
		*BytesRead = 0;
		*BytesNeeded = sizeof (NDIS_DEVICE_POWER_STATE);
	}

	DBGPRINT ("<==MPProcessSetPowerOid"); 
}







VOID
MPReturnPacket(
	IN	NDIS_HANDLE				MiniportAdapterContext,
	IN	PNDIS_PACKET			Packet
	)
/*++

Routine Description:


Arguments:


Return Value:


--*/
{
	PADAPT			pAdapt = (PADAPT)MiniportAdapterContext;
	PNDIS_PACKET	MyPacket;
	PRSVD			Resvd;

	Resvd = (PRSVD)(Packet->MiniportReserved);
	MyPacket = Resvd->OriginalPkt;

	NdisFreePacket(Packet);
	NdisReturnPackets(&MyPacket, 1);
}


NDIS_STATUS
MPTransferData(
	OUT PNDIS_PACKET			Packet,
	OUT PUINT					BytesTransferred,
	IN	NDIS_HANDLE				MiniportAdapterContext,
	IN	NDIS_HANDLE				MiniportReceiveContext,
	IN	UINT					ByteOffset,
	IN	UINT					BytesToTransfer
	)
/*++

Routine Description:

	Miniport's transfer data handler.
	�̴���Ʈ�� �ڷ� ���� �ڵ鷯

Arguments:

	Packet					���� ����Ʈ
	BytesTransferred		�󸶳� ���� �ڷᰡ ����ǿ��°��� ���� ��ġ ������
	MiniportAdapterContext	�ƴ��� ����ü������ ���ñ�
	MiniportReceiveContext	����
	ByteOffset				�ڷ� ���縦 ���� ����Ʈ������ ����
	BytesToTransfer			���簡 �󸶳� ������

Return Value:

	Status of transfer

--*/
{
	PADAPT		pAdapt = (PADAPT)MiniportAdapterContext;
	NDIS_STATUS	Status;

	//
	// Return, if the device is OFF
	// ��ġ�� OFF�̸� ����
	//

	if (IsIMDeviceStateOn(pAdapt) == FALSE)
	{
		return NDIS_STATUS_FAILURE;
	}

	//
	// All receives are to be done on the primary, will point to itself
	// ��� ���ŵ��� �������� ������ �� ��ü�� �����Ұ��Դϴ�.
	//
	pAdapt = pAdapt->pPrimaryAdapt;


	NdisTransferData(&Status,
					 pAdapt->BindingHandle,
					 MiniportReceiveContext,
					 ByteOffset,
					 BytesToTransfer,
					 Packet,
					 BytesTransferred);

	return(Status);
}

VOID
MPHalt(
	IN	NDIS_HANDLE				MiniportAdapterContext
	)
/*++

Routine Description:

	Halt handler. All the hard-work for clean-up is done here.
	LBFO - the current instance of the driver needs to be removed from the gloabal list
	���� �ڵ鷯 . ���� �ϱ����� ��� �۾��� ���⼭ ������.
	LBFO - ����̹��� ���� ��ü�� �뿪 ������κ��� ���ŵǿ��� �Ѵ�.

Arguments:

	MiniportAdapterContext	�ƴ��Ϳ����� ���ñ�

Return Value:

	None.

--*/
{
	PADAPT			pAdapt = (PADAPT)MiniportAdapterContext;
	NDIS_STATUS		Status;
	PADAPT			pCursor, *ppCursor;
	PADAPT			pPromoteAdapt = NULL;
	KIRQL			OldIrql;

	DBGPRINT ("==>Passthru MPHaltMiniport\n");

/*
	if (Globals.NdisDeviceHandle)
		NdisMDeregisterDevice(Globals.NdisDeviceHandle);
	Globals.NdisDeviceHandle = NULL;
*/
	//
	// Remove the pAdapt from our global list
	// �츮�� �뿪 ������κ��� pAdapt�� ����
	//
	// Acquire the lock and keep it untill all pointers to this pAdapt have been removed
	// from the linked list
	//
	KeAcquireSpinLock (&pAdapt->SpinLock, &OldIrql);

	//
	// Remove the padapt from the list
	//
	for (ppCursor = &pAdaptList; *ppCursor != NULL; ppCursor = &(*ppCursor)->Next)
	{
		if (*ppCursor == pAdapt)
		{
			*ppCursor = pAdapt->Next;
			break;
		}
	}

	//
	//	Remove all the pointers to pAdapt from our list
	//
	for (pCursor = pAdaptList; pCursor != NULL; pCursor = pCursor->Next)
	{
		//
		// Now pointers in our global list might become invalid. Checking for Primary
		//
		if (pCursor->pPrimaryAdapt == pAdapt)
		{
			ASSERT (pCursor->isSecondary == TRUE);

			//
			// Keep a pointer to the secondary that needs to be promoted, as it is now alone
			//
			pPromoteAdapt = pCursor;
		}

		//
		// Now checking for the secondary
		//
		if (pCursor->pSecondaryAdapt == pAdapt)
		{
			ASSERT(pCursor->isSecondary == FALSE); // Assert (pCursor is Primary);

			//
			// This is all we need to change in our internal structure, the rest of the pointers are not invalid
			//
			pCursor->pSecondaryAdapt = pCursor;
		}
	}

	KeReleaseSpinLock (&pAdapt->SpinLock, OldIrql);

	//
	// If there is a miniport that needs to be promoted, promote it.
	// Call API outside of spin lock
	//
	if (pPromoteAdapt != NULL)
	{
		MPPromoteSecondary(pPromoteAdapt);
	}

	//
	// If we have a valid bind, close the miniport below the protocol
	//
	if (pAdapt->BindingHandle != NULL)
	{
		//
		// Close the binding below. and wait for it to complete
		//
		NdisResetEvent(&pAdapt->Event);

		NdisCloseAdapter(&Status, pAdapt->BindingHandle);

		if (Status == NDIS_STATUS_PENDING)
		{
			NdisWaitEvent(&pAdapt->Event, 0);
			Status = pAdapt->Status;
		}

		ASSERT (Status == NDIS_STATUS_SUCCESS);

		pAdapt->BindingHandle = NULL;
	}


	//
	// Free the resources now
	//
	NdisFreePacketPool(pAdapt->SendPacketPoolHandle);
	NdisFreePacketPool(pAdapt->RecvPacketPoolHandle);
	NdisFreeMemory(pAdapt->BundleUniString.Buffer, MAX_BUNDLEID_LENGTH,0);


	NdisFreeMemory(pAdapt, sizeof(ADAPT), 0);

	WriteLog("Halt\n");
	DBGPRINT("<==Passthru Minport Halt\n");
}


NDIS_STATUS
MPReset(
	OUT PBOOLEAN				AddressingReset,
	IN	NDIS_HANDLE				MiniportAdapterContext
	)
/*++

Routine Description:

	Reset Handler. We just don't do anything.

Arguments:

	AddressingReset			To let NDIS know whether we need help from it with our reset
	MiniportAdapterContext	Pointer to our adapter

Return Value:


--*/
{
	PADAPT	pAdapt = (PADAPT)MiniportAdapterContext;

	DBGPRINT("<== Passthru Miniport Reset\n"); ;

	*AddressingReset = FALSE;

	return(NDIS_STATUS_SUCCESS);
}


//
// The functions that do the LBFO work and bundling.
// If LBFO is turned off, then the Set Scondary API is never called and there are no bundles
//
NDIS_STATUS
MPBundleSearchAndSetSecondary(
	IN	PADAPT			pAdapt
	)
/*++

Routine Description:
	Go through the list of passthru structures and and search for an instantiation with a 
	matching bundleid and call MPSetMiniportSecondary on that structure

Arguments:

	pAdapt -	Should point to the structure that belolngs to the miniport 
				whose bundle id will be used in the search

Return Value:

	NDIS_STATUS_SUCCESS if not operation failed. This value is also returned event if 
	no new bundles are formed

--*/
{
	NDIS_STATUS						Status = NDIS_STATUS_FAILURE;
	NDIS_STRING						NoBundle = NDIS_STRING_CONST ("<no-bundle>");
	PADAPT							pCursor	= NULL;
	PADAPT							pPrimary = NULL;
	KIRQL							OldIrql;

	do
	{
		//
		// If bundle == '<bundle id>' then this Passthru miniport will not be a part of any bundle
		//
		if (NdisEqualUnicodeString(&NoBundle, &pAdapt->BundleUniString, TRUE))
		{
			Status = NDIS_STATUS_SUCCESS;
			break;
		}

		//
		// If the Bundle Identifier is not present, ie. someone entered a NULL string,
		// this miniport will not be part of a bundle 
		//

		if (pAdapt->BundleUniString.Length == 0)
		{
			Status = NDIS_STATUS_SUCCESS;
			break;
		}

		//
		// Acquire the global pAdapt List lock
		//
		KeAcquireSpinLock (&pAdapt->SpinLock, &OldIrql);

		//
		// Searching through the global list for a Passthru with the same BundleId
		//
		for (pCursor = pAdaptList; pCursor != NULL; pCursor = pCursor->Next)
		{
			if (pCursor == pAdapt)
			{
				//
				//	Skip to next Passthru, if the cursor is pointing to me
				//
				continue;
			}

			//
			// Do a case insenstive match, if matches, set current pAdapt as secondary
			//
			if (NdisEqualUnicodeString(&pCursor->BundleUniString, &pAdapt->BundleUniString, TRUE))
			{

				//
				// Making sure this is a primary of a bundle
				//
				ASSERT (pCursor->pSecondaryAdapt == pCursor && pCursor->isSecondary == FALSE);

				pPrimary = pCursor;

				break;
			}
		}

		//
		//	Release the lock, and also bring down our Irql
		//
		KeReleaseSpinLock (&pAdapt->SpinLock, OldIrql);

		//
		//	Call our Set Secondary function, do not call at DISPATCH_LEVEL
		//
		if (pPrimary != NULL)
		{
			Status = MPSetMiniportSecondary (pAdapt, pPrimary);

			ASSERT (Status == NDIS_STATUS_SUCCESS);
		}

		//
		//	We successsfully completed our search through the list, event if I did not find any bundles
		//
		Status = NDIS_STATUS_SUCCESS;

	} while (FALSE) ;

	return Status;
}


NDIS_STATUS
MPSetMiniportSecondary (
	IN	PADAPT		Secondary,
	IN	PADAPT		Primary
	)
/*++

Routine Description:
	Call the Ndis API to set the bundle and modify internal variables to keep track of the change


Arguments:

	Secondary Should point to the structure that points to the Secondary miniport
	Primary  Should point to the structure that points to the Primary miniport

Return Value:

	NDIS_STATUS_SUCCESS if there miniport was successfully made the secondary of the primary

--*/
{
	NDIS_STATUS	Status = NDIS_STATUS_SUCCESS;

	//
	//	ensure that the 'to be' primary is not part of another bundle
	//
	ASSERT (Primary != Secondary);
	ASSERT (Primary->isSecondary == 0);
	ASSERT (Primary->pSecondaryAdapt == Primary);

#ifdef __LBFO

//	DBGPRINT ("Calling NdisMSetSecondary API on the two handles\n");

	Status = NdisMSetMiniportSecondary(Secondary->MiniportHandle,
									   Primary->MiniportHandle);

	ASSERT (Status == NDIS_STATUS_SUCCESS);

	if (Status == NDIS_STATUS_SUCCESS)
	{
		//
		// Initialize the LBFO variables, to record the current state.
		//
		//
		Secondary->isSecondary = TRUE;
		Secondary->pPrimaryAdapt = Primary;
		Primary->pSecondaryAdapt = Secondary;

		//
		// Making sure that the other internal state variables have the correct value
		//
		Secondary->pSecondaryAdapt = Secondary;
		Primary->pPrimaryAdapt = Primary;
		Primary->isSecondary = FALSE;
	}

#endif

	return Status;
}


NDIS_STATUS
MPPromoteSecondary(
	IN	PADAPT		pAdapt
	)
/*++

Routine Description:

	Does the Passthru book keeping to promote a
	Passthru instantiation from a secondary to a primary miniport

Arguments:

	pAdapt - Pointer to the internal adapter structure

Return Value:

	NDIS_STATUS_SUCCESS - if success

	Otherwise the return value of the NdisMPromoteMiniport API
--*/
{
	NDIS_STATUS Status;

//	DBGPRINT ("==> MPPromoteMiniport\n");

	Status = NdisMPromoteMiniport(pAdapt->MiniportHandle);


	ASSERT (Status == NDIS_STATUS_SUCCESS);

	if (Status == NDIS_STATUS_SUCCESS)
	{
		pAdapt->isSecondary = FALSE;

		pAdapt->pPrimaryAdapt = pAdapt;

		pAdapt->pSecondaryAdapt = pAdapt;
	}

//	DBGPRINT ("<== MPPromoteMiniport\n");

	return Status;
}


BOOLEAN
MPIsSendOID (
	IN	NDIS_OID	Oid
	)
/*++

Routine Description:

		Indicates if an OID should be routed to the Send miniport. Right now, the list comprises of those OIDs which drivers
		running ethernet must support (See General Objects in the DDK). In this implementation, all OIDS are Query Oids


Arguments:

		Oid - The oid in question
Return Value:
		True  if Oid should be sent to the Send miniport
		False if Oid should be sent to the Receive miniport - default

--*/
{
	BOOLEAN fIsSend = FALSE;	//default : it is a receive  OID

	switch (Oid)
	{
		//
		// If OID needs to be sent to the Send miniport, set the boolean flag
		//
		case OID_GEN_TRANSMIT_BUFFER_SPACE :
		case OID_GEN_TRANSMIT_BLOCK_SIZE :
		case OID_GEN_MAXIMUM_TOTAL_SIZE :

		//
		// OIds used to collect transmission statistics
		//
		case OID_GEN_XMIT_OK :
		case OID_GEN_XMIT_ERROR :
		case OID_GEN_DIRECTED_BYTES_XMIT :
		case OID_GEN_DIRECTED_FRAMES_XMIT :
		case OID_GEN_MULTICAST_BYTES_XMIT :
		case OID_GEN_MULTICAST_FRAMES_XMIT :
		case OID_GEN_BROADCAST_BYTES_XMIT :
		case OID_GEN_BROADCAST_FRAMES_XMIT :
		case OID_GEN_TRANSMIT_QUEUE_LENGTH :
			fIsSend = TRUE;
			break;

		default:
			fIsSend = FALSE;
			break;
	}

	return fIsSend;
}


