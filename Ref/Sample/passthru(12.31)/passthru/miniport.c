/*++

Copyright (c) 1992  Microsoft Corporation

Module Name:

	miniport.c

Abstract:

	Ndis 중간 미니포트 드라이버 실례. 이것이 passthru 드라이버입니다.

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

	이것은 NdisIMInitializeDeviceInstanceEx()를 호출하는 BindAdapter 핸들러의 결과로 호출되는 
	초기화 핸들러입니다. 우리가 통과시키는 context 파라메터는 우리가 여기서 다시 고치는 
	adapter 구조체입니다. 우리는 또한 전원 관리 변수를 초기화해야 합니다.
	
	LoadBalalncing- 우리는 설치된 모든 passthru 미니포트들의 대역 목록 및 
	같은 BundleId가 있으면 (레지스트리에서 읽는다)그것들 둘다의 반들 목록을 유지합니다.

	인수들:

	OpenErrorStatus			우리가 사용하지 않습니다.
	SelectedMediumIndex		우리가 사용하고 있는 매체에 대한 위치 유지기
	MediumArray				우리에게 아래 통과되는 ndis 매체의 배렬
	MediumArraySize			배렬의 크기
	MiniportAdapterHandle	우리와 관련하기 위해 NDIS 가 사용하는 핸들러
	WrapperConfigurationContext	NdisOpenConfiguration에 의한 사용을 위해 필요

돌림값:

	NDIS_STATUS_SUCCESS 아무것도 이상이 없으면

--*/
{
	UINT	i;
	PADAPT	pAdapt;
	NDIS_STATUS						Status = NDIS_STATUS_FAILURE;


	NDIS_STATUS						BundleStatus = NDIS_STATUS_FAILURE;
	NDIS_STRING						BundleUniString;
	KIRQL							OldIrql;
	//
	// adapter 문맥 검색과 거기에 있는 미니포트 핸들러 저장에 의한 시작
	//
	DBGPRINT("==>Passthru Initialize Miniport\n");
 	AddLog("==>Passthru Initialize Miniport\n");

	pAdapt = NdisIMGetDeviceContext(MiniportAdapterHandle);
	pAdapt->MiniportHandle = MiniportAdapterHandle;

	//
	// Make sure the medium saved is one of the ones being offered
	// 보관된 매체가 제공된 것들중 하나인가를 확인
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

	// 지금 속성 설정. NDIS_ATTRIBUTE_DESERIALIZE 는 키이다. 이것은 우리로 하여금 NDIS w/o가 
	// NdisIMSwitchToMiniport/NdisIMQueueCallBack를 호출하도록 호출을 만들게 합니다.
	// 이것은 또한 우리가 spinlocks를 적당히 사용하여 우리의 자료를 보호하도록 요구합니다.
	// 또한 이경우에 NDIS는 바깓 측면에서 파케트들을 대기시키지 않습니다. 이것이 매우 간단한 
	// pass-thru 미니포트이기때문에 우리는 아무것도 보호할 필요가 없습니다. 그러나 일반 경우에
	// 가장 최소한 파케트가 대기하는데 대해 아답터를 통한 spin-locks를 사용해야 할것입니다.
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
	// 장치 상태에 대해 기정값 설정. PM은 PM 변수를 초기화할수 있고 (미니포트와 프로토콜 둘다)
	// 장치는 기정으로 ON
	//
	pAdapt->MPDeviceState=NdisDeviceStateD0;
	pAdapt->PTDeviceState=NdisDeviceStateD0;

	//
	// Begin the Load Balancing and Bundle Identifier work here
	// Default case: the miniport is the primary miniport
	// 균형 맞추기와 반들 식별자 적재 작업을 여기서 시작
	// 기정 경우: 미니포트는 일차 미니포트
	//
	pAdapt->isSecondary		=	FALSE;	// 기정 - 일차
	pAdapt->pPrimaryAdapt	=	pAdapt;	//기정, 자체를 지적
	pAdapt->pSecondaryAdapt	=	pAdapt;	//기정, 자체를 지적

	//
	// Set miniport as a secondary miniport, if need be
	// 필요하면 미니포트를 이차 미니포트로 설정
	//
	BundleStatus  =	MPBundleSearchAndSetSecondary (pAdapt);

	//
	// Inserting into our global Passthru pAdapt List
	// 우리의 대역 Passthru pAdapt 목록에 추가
	//
	KeAcquireSpinLock (&pAdapt->SpinLock, &OldIrql);

	pAdapt->Next = pAdaptList;
	pAdaptList = pAdapt;

	KeReleaseSpinLock (&pAdapt->SpinLock, OldIrql);
		
	//
	// We are done, In current implementation, Bundle Status does not affect the success of initialization
	// 끝. 현재 수행에서 반들 상태는 초기화의 성공에 영향을 주지않는다
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
		// 새로운 파케트에 본래 파케트의 OOB 변위를 복사.
		//

		NdisMoveMemory(NDIS_OOB_DATA_FROM_PACKET(pPassPacket->Packet),
					   NDIS_OOB_DATA_FROM_PACKET(srcPacket),
					   sizeof(NDIS_PACKET_OOB_DATA));


		//
		// Copy the per packet info into the new packet
		// This includes ClassificationHandle, etc.
		// Make sure other stuff is not copied !!!
		// 새로운 파케트에 파케트 정보를 복사
		// 이것은 ClassificationHandle, 등을 포함한다.
		// 다른 stuff가 복사되지 않는지 확인 !!!
		//

		NdisIMCopySendPerPacketInfo(pPassPacket->Packet, srcPacket);
		
		//
		// Copy the Media specific information
		// 매체 특정 정보 복사
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

	송신 핸들러. 여기서 파케트를 재포장하고 그것을 아래로 송신합니다. 재 포장은 NDIS가 
	그의 자체 사용을 위해 WrapperReserved를 사용할때 필요합니다.
	
	LBFO- All sends will be done in the secondary miniport of the bundle.
	LBFO- 모든 송신들은 반들의 이차 미니포트에서 끝날것입니다.

	We are using the Secondary Miniport as the Send path. All sends should use that pAdapt structure.
	우리는 이차 미니포트를 송신 경로로 사용하고 있습니다.
	모든 송신들은 해당 pAdapt 구조체를 사용해야 합니다.

Arguments:

	MiniportAdapterContext	아답터에로릐 지시기
	Packet					송신하려는 파케트
	Flags					사용되지 않음, 아래로 통과됨

Return Value:

	Return code from NdisSend
	NdisSend로부터 온 코드를 리턴

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
	//  우리의 LBFO 설계에 의하면 모든 송신들은 이차 미니포트에서 수행될것입니다.
	//	그러나 일차 미니포트 핸들에서 완료되여야 합니다.
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
	미니포트 QueryInfo 핸들러.
	전원 관리 시나리오에서 OID_PNP_QUERY_POWER 는 기초 미니포트에 보내지지 않습니다.
	OID_PNP_CAPABILITES 는 미니포트 아래로 요청으로 통과됩니다.
	결과가 성공이면 InformationBuffer는 the MPQueryPNPCapabilites에서 채워집니다.

	LBFO - For present all queries are passed on to the miniports that they were requested on.
	LBFO - 현재 모든 질의들은 그것들이 요청된 미니포트들에로 통과됩니다.

	PM- If the MP is not ON (DeviceState > D0) return immediately  (except for query power and set power)
         If MP is ON, but the PT is not at D0, then queue the queue the request for later processing
	PM- MP 가 ON 이아니면 (DeviceState > D0) 직접 리턴 (전원 질의와 전원 설정을 내놓고)
         MP 가 ON 이지만 PT 가 D0 에 있지 않으면 마지막 처리에 대한 요청을 대기렬에 대기한다.

	Requests to miniports are always serialized
	미니포트들에로의 요청들은 이미 직렬화되였다.

Arguments:

	MiniportAdapterContext	아답터 구조체에로의 지시기
	Oid						이 질의에 대한 Oid
	InformationBuffer		정보 완충기
	InformationBufferLength	이 완충기의 크기
	BytesWritten			얼마나 많은 정보가 작성되였는지 지정
	BytesNeeded				In case the buffer is smaller than what we need, tell them how much is needed
							완충기가 필요한것보다 작은경우 얼마나 필요한지 알린다


Return Value:

	Return code from the NdisRequest below.
	NdisRequest 로부터 온 코드를 아래로 리턴한다.

--*/
{
	PADAPT	pAdapt = (PADAPT)MiniportAdapterContext;
	NDIS_STATUS	Status = NDIS_STATUS_FAILURE;

	do
	{
		//
		// Return Success for this OID
		// 이 OID에 대해 성공을 리턴
		//
		if (Oid == OID_PNP_QUERY_POWER)
		{
			Status=NDIS_STATUS_SUCCESS;
			break;
		}

		//
		// All other queries are failed, if the miniport is not at D0
		// 만일 미니포트가 D0이 아니면 모든 다른 요청들은 실패
		//
		if (pAdapt->MPDeviceState > NdisDeviceStateD0 || pAdapt->StandingBy == TRUE)
		{
			Status = NDIS_STATUS_FAILURE;
			break;
		}
		//
		//	We are doing all sends on the secondary, so send all requests with Send OIDs to the Secondary
		//	우리는 이차에서 모든 송신들을 수행하여 이차에로 송신 OID들을 가진 모든 요청들을 송신하였다.
		//
		if (MPIsSendOID(Oid))
		{
			pAdapt = pAdapt->pSecondaryAdapt;
			//
			// Will point to itself, if there is no secondary (see initialization)
			// 만일 이차가 없으면 그 자체를 가리킬것이다.(초기화를 보라)
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
		// 프로토콜 장치 상태가 OFF이면 IM 드라이버는 요청들을 아래로 송신할수 없으며 그것을 미결로 남겨야 한다.
		//
		if (pAdapt->PTDeviceState > NdisDeviceStateD0)
		{
			pAdapt->QueuedRequest = TRUE;
			Status = NDIS_STATUS_PENDING;
			break;
		}

		//
		// default case, most requests will be passed to the miniport below
		// 기정 경우 대부분의 요청들은 미니포트 아래로 통과될것이다
		//
		NdisRequest(&Status,
					pAdapt->BindingHandle,
					&pAdapt->Request);


		//
		// If the Query was a success, pass the results back to the entity that made the request
		// 질의가 성공하면 요청을 만드는 엔티티에로 결과를 거꾸로 보낸다.
		//
		if (Status == NDIS_STATUS_SUCCESS)
		{
			*BytesWritten = pAdapt->Request.DATA.QUERY_INFORMATION.BytesWritten;
			*BytesNeeded = pAdapt->Request.DATA.QUERY_INFORMATION.BytesNeeded;
		}

		//
		// Fill the buffer with the required values if Oid == OID_PNP_CAPABILITIES
		// and the query was successful
		// Oid == OID_PNP_CAPABILITIES이고 질의가 성공하면 요청된 값으로 완충기를 채운다
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
	Oid == Oid_PNP_CAPABILITIES이면 InformationBuffer 는 NDIS_PM_WAKE_UP_CAPABILITIES 구조체에
	모든 마당들을 NdisDeviceStateUnspecified 로 할당하여 리턴됩니다.

	OID_QUERY_POWER_STATE is returned with NDIS_STATUS_SUCCESS and should never be passed below.
	OID_QUERY_POWER_STATE 는 NDIS_STATUS_SUCCESS 로 리턴되며 아래로 통과되지 말아야 합니다.

Arguments:

	MiniportAdapterContext	아답터 구조체에로의 지시기
	Oid						이 질의에 대한 Oid
	InformationBuffer		정보 완충기
	InformationBufferLength	이 완충기의 크기
	BytesWritten			얼마나 많은 정보가 작성되였는지 지적
	BytesNeeded				In case the buffer is smaller than what we need, tell them how much is needed
							완충기가 필요한랑보다 작으면 얼마나 필요한지 알린다

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
		// Passthru 미니포트 웃쪽의 프로토콜에 리턴되는 완충기를 설정한다.
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
		// 우리의 내부 기발들을 설정
		// 기정으로 장치는 ON
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

	미니포트 SetInfo 핸들러.

	In the case of OID_PNP_SET_POWER, record the power state and return the OID.	
	Do not pass below
	If the device is suspended, do not block the SET_POWER_OID 
	as it is used to reactivate the Passthru miniport
	OID_PNP_SET_POWER의 경우 전원 상태를 기록하고 OID를 리턴한다.
	아래로 통과시키지 말것
	장치가 매달려 있으면 Passthru 미니포트를 재활성화 하는데 사용되도록 
	SET_POWER_OID를 차단하지 마십시오.

	
	PM- If the MP is not ON (DeviceState > D0) return immediately  (except for 'query power' and 'set power')
         If MP is ON, but the PT is not at D0, then queue the queue the request for later processing
	PM- MP 가 ON이 아니면 (DeviceState > D0) 직접 리턴('query power' 와 'set power'에 대해서는 제외)
         MP 가 ON이지만 PT 가 D0이 아니면 마지막 처리에 대한 요청을 대기렬에 대기

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
		// 전원 설정은 Passthru 아래의 미니포트에 송신되지 말아야 하지만 내적으로 조종된다
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
		// 미니포트가 D0이 아니거나 장치 상태가 D0보다 크게 변경되면 모든 다른 정보 설정 요청들은 실패된다.
		//
		if (pAdapt->MPDeviceState > NdisDeviceStateD0 || pAdapt->StandingBy == TRUE)
		{
			Status = NDIS_STATUS_FAILURE;
			break;
		}


		// Set up the Request and return the result
		// 요청을 설정하고 결과를 리턴
		pAdapt->Request.RequestType = NdisRequestSetInformation;
		pAdapt->Request.DATA.SET_INFORMATION.Oid = Oid;
		pAdapt->Request.DATA.SET_INFORMATION.InformationBuffer = InformationBuffer;
		pAdapt->Request.DATA.SET_INFORMATION.InformationBufferLength = InformationBufferLength;
		pAdapt->BytesNeeded = BytesNeeded;
		pAdapt->BytesReadOrWritten = BytesRead;
		pAdapt->OutstandingRequests = TRUE;


		//
		// if the Protocol device state is OFF, then the IM driver cannot send the request below and must pend it
		// 프로토콜 장치 상태가 OFF이면 IM 드라이버는 요청을 아래로 송신할수 없으며 그것을 미결로 남겨야 한다.
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
	이 루틴은 SetPower Oid를 가진 요청에 대해 모든 처리를 진행합니다.
    SampleIM 미니포트는 전원 설정을 접수하고 새로운 상태로 이행해야 합니다.

    The Set Power should not be passed to the miniport below
    전원 설정은 미니포트 아래로 통과되지 말아야 합니다.

    If the IM miniport is going into a low power state, then there is no guarantee if it will ever
    be asked go back to D0, before getting halted. No requests should be pended or queued.
    만일 IM 미니포트가 낮은 전원 상태로 가면 정지되기 전에 D0으로 돌아가도록 
	항상 물어볼것이라는 담보가 없습니다. 미결로 되거나 대기되여야 하는 요청들은 없습니다.

	
Arguments:
	IN OUT PNDIS_STATUS      *pNdisStatus - 조작의 상태
	IN  PADAPT					pAdapt,   - 아답터 구조체 
	IN	PVOID					InformationBuffer, - 새로운 장치 상태 
	IN	ULONG					InformationBufferLength,
	OUT PULONG					BytesRead, - 읽은 바이트 수 
	OUT PULONG					BytesNeeded -  필요한 바이트 수 


Return Value:
    Status  - 모든 대기 사건들이 성공하면 NDIS_STATUS_SUCCESS
    

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
		// 무효한 길이 검사 
		//
		if (InformationBufferLength < sizeof(NDIS_DEVICE_POWER_STATE))
		{
			*pNdisStatus = NDIS_STATUS_INVALID_LENGTH;
			break;
		}

		//
		// Check for invalid device state
		// 무효한 장치 상태 검사
		//
		if ((pAdapt->MPDeviceState > NdisDeviceStateD0) && (NewDeviceState != NdisDeviceStateD0))
		{
			//
			// If the miniport is in a non-D0 state, the miniport can only receive a Set Power to D0
			// 미니포트가 D0 상태가 아니면 미니포트는 전원을 D0으로 설정을 수신할수만 있습니다.
			//
			ASSERT (!(pAdapt->MPDeviceState > NdisDeviceStateD0) && (NewDeviceState != NdisDeviceStateD0));

			*pNdisStatus = NDIS_STATUS_FAILURE;
			break;
		}	

		//
		// Is the miniport transitioning from an On (D0) state to an Low Power State (>D0)
		// If so, then set the StandingBy Flag - (Block all incoming requests)
		// 미니포트가 On (D0) 상태로부터 낮은 전원 상태 (>D0)로 변환되는가?
		// 그렇다면 StandingBy 기발을 설정 (들어오는 요청들을 모두 차단)
		//
		if (pAdapt->MPDeviceState == NdisDeviceStateD0 && NewDeviceState > NdisDeviceStateD0)
		{
			pAdapt->StandingBy = TRUE;
		}

		//
		// If the miniport is transitioning from a low power state to ON (D0), then clear the StandingBy flag
		// All incoming requests will be pended until the physical miniport turns ON.
		// 미니포트가 낮은 전원 상태로부터 ON (D0)으로 변환되면 StandingBy 기발을 해제
		// 들어오는 모든 요청들은 물리 미니포트가 ON으로 될때까지 미결로 될것입니다.
		//
		if (pAdapt->MPDeviceState > NdisDeviceStateD0 &&  NewDeviceState == NdisDeviceStateD0)
		{
			pAdapt->StandingBy = FALSE;
		}
		
		//
		// Now update the state in the pAdapt structure;
		// pAdapt 구조체의 상태를 갱신;
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
	미니포트의 자료 전송 핸들러

Arguments:

	Packet					목적 파케트
	BytesTransferred		얼마나 많은 자료가 복사되였는가에 대한 위치 유지기
	MiniportAdapterContext	아답터 구조체에로의 지시기
	MiniportReceiveContext	문맥
	ByteOffset				자료 복사를 위한 파케트에로의 변위
	BytesToTransfer			복사가 얼마나 많은가

Return Value:

	Status of transfer

--*/
{
	PADAPT		pAdapt = (PADAPT)MiniportAdapterContext;
	NDIS_STATUS	Status;

	//
	// Return, if the device is OFF
	// 장치가 OFF이면 리턴
	//

	if (IsIMDeviceStateOn(pAdapt) == FALSE)
	{
		return NDIS_STATUS_FAILURE;
	}

	//
	// All receives are to be done on the primary, will point to itself
	// 모든 수신들은 일차에서 끝나며 그 자체를 지적할것입니다.
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
	중지 핸들러 . 삭제 하기위한 모든 작업은 여기서 끝난다.
	LBFO - 드라이버의 현재 실체는 대역 목록으로부터 제거되여야 한다.

Arguments:

	MiniportAdapterContext	아답터에로의 지시기

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
	// 우리의 대역 목록으로부터 pAdapt를 삭제
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


