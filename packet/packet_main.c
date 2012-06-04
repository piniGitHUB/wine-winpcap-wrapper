#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "wine/debug.h"

#include "packet32.h"
#include "stdio.h"
#include "wine/unicode.h"
#include <pcap/pcap.h>

WINE_DEFAULT_DEBUG_CHANNEL(packet);


char PacketLibraryVersion[64] = "4.1.0.2001";
char PacketDriverVersion[64] = "4.1.0.2001";
char errbuf[PCAP_ERRBUF_SIZE];

typedef VOID (*GAAHandler)( ULONG, DWORD, PVOID, PIP_ADAPTER_ADDRESSES , PULONG);
GAAHandler g_GetAdaptersAddressesPointer = NULL;

HANDLE g_AdaptersInfoMutex = NULL;
PADAPTER_INFO g_AdaptersInfoList = NULL;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    TRACE("(0x%p, %d, %p)\n", hinstDLL, fdwReason, lpvReserved);

    switch (fdwReason)
    {
        case DLL_WINE_PREATTACH:
            return FALSE;    /* prefer native version */
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            break;
    }

    return TRUE;
}

static void StringCchCopyA(char *pszDest,size_t cbDest, const char* pszSrc)
{
        if (cbDest == 0 || pszDest == NULL || pszSrc == NULL)
                return;
        pszDest[cbDest - 1] = '\0';
        lstrcpynA(pszDest, pszSrc, cbDest - 1);
/* FIXME:  n is an INT but Windows treats it as unsigned, and will happily
 * copy a gazillion chars if n is negative. Maybe there is a BUG here.
 */

}

static void StringCchPrintfA(char *pszDest,size_t cbDest, const char *pszFormat, ...)
{
        va_list marker;
        va_start( marker, pszFormat );     /* Initialize variable arguments. */

        if (cbDest == 0 || pszDest == NULL || pszFormat == NULL)
                return;


        pszDest[cbDest - 1] = '\0';
        vsnprintf(pszDest, cbDest - 1, pszFormat,  marker);

        va_end(marker);
}

BOOLEAN GetMacAddressByName(PCHAR Name, UCHAR Addr[6])
{
        PIP_ADAPTER_ADDRESSES pAddresses = NULL;
        ULONG ulOutBufLength = 0;
        DWORD Ret = 0;
        PCHAR tmpName;
        CHAR device_prefix[12]="\\Device\\NPF_";
        if (strncmp(Name, device_prefix, 12) == 0)
        {
                tmpName = Name + 12;
                FIXME("Force remove prefix!\n");
        }
        else
        {
                tmpName = Name;
        }

        Ret = GetAdaptersAddresses(AF_INET, 0, NULL, NULL, &ulOutBufLength);

        if (Ret == ERROR_BUFFER_OVERFLOW)
        {
                pAddresses = (PIP_ADAPTER_ADDRESSES)HeapAlloc(GetProcessHeap(), 0, ulOutBufLength);
        }

        if ( GetAdaptersAddresses(AF_INET, 0, NULL, pAddresses, &ulOutBufLength) == ERROR_SUCCESS)
        {
                PIP_ADAPTER_ADDRESSES pCurrentAddr = pAddresses;

                while (pCurrentAddr)
                {
                        if (lstrcmpA(pCurrentAddr->AdapterName, tmpName) == 0)
                        {
                                Addr[0] = pCurrentAddr->PhysicalAddress[0];
                                Addr[1] = pCurrentAddr->PhysicalAddress[1];
                                Addr[2] = pCurrentAddr->PhysicalAddress[2];
                                Addr[3] = pCurrentAddr->PhysicalAddress[3];
                                Addr[4] = pCurrentAddr->PhysicalAddress[4];
                                Addr[5] = pCurrentAddr->PhysicalAddress[5];
                                return TRUE;
                        }
                        pCurrentAddr = pCurrentAddr->Next;
                }
        }

        if (pAddresses)
        {
                HeapFree(GetProcessHeap(), 0, pAddresses);
                pAddresses = NULL;
        }

        return FALSE;
}

BOOLEAN PacketRequest(LPADAPTER  AdapterObject,BOOLEAN Set,PPACKET_OID_DATA
OidData)
{
	//DWORD		BytesReturned;
	BOOLEAN		Result;

	FIXME("Stub: AdapterObject:%p, Set:%d, OidData: %p\n", AdapterObject,
Set, OidData);

	if(AdapterObject->Flags != INFO_FLAG_NDIS_ADAPTER)
	{
		FIXME("PacketRequest not supported on non-NPF/NPFIM adapters.\n");
		return FALSE;
	}

	//Result=(BOOLEAN)DeviceIoControl(AdapterObject->hFile,(DWORD) Set ?  (DWORD)BIOCSETOID : (DWORD)BIOCQUERYOID, OidData,sizeof(PACKET_OID_DATA)-1+OidData->Length,OidData, sizeof(PACKET_OID_DATA)-1+OidData->Length,&BytesReturned,NULL);

        switch (OidData->Oid)
        {
            case OID_GEN_MEDIA_CONNECT_STATUS:
                 OidData->Data[0]=0;
                 FIXME("OID_GEN_MEDIA_CONNECT_STATUS, Always reports connected!\n");
                 break;

            case OID_802_3_PERMANENT_ADDRESS:
            case OID_802_3_CURRENT_ADDRESS:
                 if (!GetMacAddressByName(AdapterObject->Name, OidData->Data))
                 {
                         OidData->Data[0]=0x00;
                         OidData->Data[1]=0x11;
                         OidData->Data[2]=0x22;
                         OidData->Data[3]=0x33;
                         OidData->Data[4]=0x44;
                         OidData->Data[5]=0x55;

                         FIXME("Get mac address failed, fills with fake address!\n");
                 }
                 FIXME("MAC is %.02x:%.02x:%.02x:%.02x:%.02x:%.02x\n", OidData->Data[0], OidData->Data[1], OidData->Data[2], OidData->Data[3], OidData->Data[4], OidData->Data[5]);
                 break;

            default:
                 FIXME("Unimplemented Oid type: %.08x\n", OidData->Oid);
                 break;
        }
    
        Result=TRUE; /*FIXME: force return true */
	// output some debug info
	FIXME("PacketRequest, OID=%.08x Length=%.05d Set=%.04d Res=%.04d\n", OidData->Oid, OidData->Length, Set, Result);

	return Result;
}



BOOLEAN PacketSetMaxLookaheadsize (LPADAPTER AdapterObject)
{
	BOOLEAN    Status;
	ULONG      IoCtlBufferLength=(sizeof(PACKET_OID_DATA)+sizeof(ULONG)-1);
	PPACKET_OID_DATA  OidData;

	FIXME("PacketSetMaxLookaheadsize\n");

	OidData = GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT,IoCtlBufferLength);
	if (OidData == NULL) {
		FIXME("PacketSetMaxLookaheadsize failed\n");
		Status = FALSE;
	}
	else
	{
		//set the size of the lookahead buffer to the maximum available
		//by the the NIC driver
		OidData->Oid=OID_GEN_MAXIMUM_LOOKAHEAD;
		OidData->Length=sizeof(ULONG);
		Status=PacketRequest(AdapterObject,FALSE,OidData);
		OidData->Oid=OID_GEN_CURRENT_LOOKAHEAD;
		Status=PacketRequest(AdapterObject,TRUE,OidData);
                TRACE("PacketRequest, OID=%.08x Length=%.05d \n", OidData->Oid, OidData->Length);
		(void)GlobalFreePtr(OidData);
	}

	return Status;
}

BOOLEAN PacketSetReadEvt(LPADAPTER AdapterObject)
{
	DWORD BytesReturned;
	HANDLE hEvent;

 	FIXME("PacketSetReadEvt\n");

	if (AdapterObject->ReadEvent != NULL)
	{
		SetLastError(ERROR_INVALID_FUNCTION);
		return FALSE;
	}

 	hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);

	if (hEvent == NULL)
	{
		//SetLastError done by CreateEvent	
                ERR("hEvent is NULL!!\n");
		return FALSE;
	}

	if(DeviceIoControl(AdapterObject->hFile, BIOCSETEVENTHANDLE, &hEvent, sizeof(hEvent), NULL, 0, &BytesReturned, NULL)==FALSE) 
	{
		/*
                DWORD dwLastError = GetLastError();

		CloseHandle(hEvent);

		SetLastError(dwLastError);

		return FALSE;
                */
	}

	AdapterObject->ReadEvent = hEvent;
        FIXME("hEvent is %p \n", AdapterObject->ReadEvent);
	AdapterObject->ReadTimeOut=0;

	return TRUE;
}

LPADAPTER PacketOpenAdapterNPF(PCHAR AdapterNameA)
{
	LPADAPTER lpAdapter;
	DWORD error;
	CHAR SymbolicLinkA[MAX_PATH];

	FIXME("PacketOpenAdapterNPF\n");
	FIXME("Trying to open adapter %s\n", AdapterNameA);

	lpAdapter=(ADAPTER *)GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT, sizeof(ADAPTER));
	if (lpAdapter==NULL)
	{
		FIXME("PacketOpenAdapterNPF: GlobalAlloc Failed to allocate the ADAPTER structure\n");
		error=GetLastError();
		//set the error to the one on which we failed
		SetLastError(error);
		return NULL;
	}

	lpAdapter->NumWrites=1;

#define DEVICE_PREFIX "\\Device\\"

	if (LOWORD(GetVersion()) == 4)
	{
		if (strlen(AdapterNameA) > strlen(DEVICE_PREFIX))
		{
			StringCchPrintfA(SymbolicLinkA, MAX_PATH, "\\\\.\\%s",
AdapterNameA + strlen(DEVICE_PREFIX));
		}
		else
		{
			ZeroMemory(SymbolicLinkA, sizeof(SymbolicLinkA));
		}
	}
	else
	{
		if (strlen(AdapterNameA) > strlen(DEVICE_PREFIX))
		{
			StringCchPrintfA(SymbolicLinkA, MAX_PATH, "\\\\.\\Global\\%s", AdapterNameA + strlen(DEVICE_PREFIX));
		}
		else
		{
			ZeroMemory(SymbolicLinkA, sizeof(SymbolicLinkA));
		}
	}

	//
	// NOTE GV 20061114 This is a sort of breaking change. In the past we
	// were putting what
	// we could fit inside this variable. Now we simply put NOTHING. It's
	// just useless
	//
	ZeroMemory(lpAdapter->SymbolicLink, sizeof(lpAdapter->SymbolicLink));

	//try if it is possible to open the adapter immediately
	CreateDirectoryA("\\\\.\\Global",NULL);
	lpAdapter->hFile=CreateFileA("C:\\windows\\debug.txt" , GENERIC_WRITE | GENERIC_READ, 0,NULL,CREATE_ALWAYS,0,0);
        CloseHandle(lpAdapter->hFile);
	//lpAdapter->hFile=CreateFileA(SymbolicLinkA,GENERIC_WRITE | GENERIC_READ, 0,NULL,OPEN_EXISTING,0,0);
	lpAdapter->hFile=CreateFileA("C:\\windows\\debug.txt",GENERIC_WRITE | GENERIC_READ, 0,NULL, OPEN_EXISTING,0,0);

	if (/* lpAdapter->hFile != INVALID_HANDLE_VALUE*/ TRUE )
	{

		if(PacketSetReadEvt(lpAdapter)==FALSE/* FALSE*/){
			error=GetLastError();
			FIXME("PacketOpenAdapterNPF: Unable to open the read event\n");
			CloseHandle(lpAdapter->hFile);
			(void)GlobalFreePtr(lpAdapter);
			//set the error to the one on which we failed

			FIXME("PacketOpenAdapterNPF: PacketSetReadEvt failed, LastError=%8.8x\n",error);

			SetLastError(error);
			return NULL;
		}		

		PacketSetMaxLookaheadsize(lpAdapter);

		//
		// Indicate that this is a device managed by NPF.sys
		//
		lpAdapter->Flags = INFO_FLAG_NDIS_ADAPTER;


		StringCchCopyA(lpAdapter->Name, ADAPTER_NAME_LENGTH, AdapterNameA);

		FIXME("Successfully opened adapter: %s -> %p, returned %p\n", lpAdapter->Name, lpAdapter->Name, lpAdapter);
		return lpAdapter;
	}

	error=GetLastError();
	(void)GlobalFreePtr(lpAdapter);
	//set the error to the one on which we failed
	FIXME("PacketOpenAdapterNPF: CreateFile failed, LastError= %8.8x\n",error);
	SetLastError(error);
	return NULL;
}

static BOOLEAN PacketAddAdapterIPH(PIP_ADAPTER_INFO IphAd)
{
	PADAPTER_INFO TmpAdInfo, SAdInfo;
	PIP_ADDR_STRING TmpAddrStr;
	UINT i;
	struct sockaddr_in *TmpAddr;
	CHAR TName[256];
	//LPADAPTER adapter;
	//CHAR	npfCompleteDriverPrefix[MAX_WINPCAP_KEY_CHARS] = NPF_DRIVER_COMPLETE_DEVICE_PREFIX;

	FIXME("PacketAddAdapterIPH\n");

// Create the NPF device name from the original device name
//  
//	Old registry based WinPcap names
//
//	RegQueryLen =
//	sizeof(npfCompleteDriverPrefix)/sizeof(npfCompleteDriverPrefix[0]);
//	
//	if
//	(QueryWinPcapRegistryStringA(NPF_DRIVER_COMPLETE_DEVICE_PREFIX_REG_KEY,
//	npfCompleteDriverPrefix, &RegQueryLen,
//	NPF_DRIVER_COMPLETE_DEVICE_PREFIX) == FALSE && RegQueryLen == 0)
//		return FALSE;
//
//	// Create the NPF device name from the original device name
//	_snprintf(TName,
//		sizeof(TName) - 1 - RegQueryLen - 1, 
//		"%s%s",
//		npfCompleteDriverPrefix, 
//		IphAd->AdapterName);

	// Create the NPF device name from the original device name
	//StringCchPrintfA(TName, sizeof(TName) - strlen(npfCompleteDriverPrefix), "%s%s", npfCompleteDriverPrefix, IphAd->AdapterName);
        lstrcpyA(TName, IphAd->AdapterName);

	// Scan the adapters list to see if this one is already present
	for(SAdInfo = g_AdaptersInfoList; SAdInfo != NULL; SAdInfo = SAdInfo->Next)
	{
		if(lstrcmpA(TName, SAdInfo->Name) == 0)
		{
			FIXME("PacketAddAdapterIPH: Adapter %s already present in the list\n", TName);
			goto SkipAd;
		}
	}

	if(IphAd->Type == IF_TYPE_PPP || IphAd->Type == IF_TYPE_SLIP)
	{
		goto SkipAd;
	}

	else
	{
		FIXME("Trying to open adapter %s to see if it's available...\n", TName);
		//PacketOpenAdapterNPF(TName);  //FIXME: why?
                FIXME("Tried. For debug. \n");
		if(/*adapter == NULL*/ FALSE)
		{
			// We are not able to open this adapter. Skip to the
			// next one.
			ERR("PacketAddAdapterIPH: unable to open the adapter %s\n", TName);
			goto SkipAd;
		}

		else
		{
			FIXME("PacketAddAdapterIPH: adapter %s is available\n", TName);
			/*PacketCloseAdapter(adapter);*/
		}
	}	

	// 
	// Adapter valid and not yet present in the list. Allocate the
	// ADAPTER_INFO structure
	//
	FIXME("Adapter %s is available and should be added to the global list...\n", TName);

	TmpAdInfo = GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT,
sizeof(ADAPTER_INFO));

	if (TmpAdInfo == NULL) 
	{
		FIXME("PacketAddAdapterIPH: GlobalAlloc Failed allocating memory for the AdInfo\n");
		return FALSE;
	}

	// Copy the device name
	StringCchCopyA(TmpAdInfo->Name,ADAPTER_NAME_LENGTH, TName);
        FIXME("TmpAdInfo->Name is %s\n", TmpAdInfo->Name);
	
	// Copy the description
	StringCchCopyA(TmpAdInfo->Description, ADAPTER_DESC_LENGTH, IphAd->Description);
        FIXME("TmpAdInfo->Description is %s\n", TmpAdInfo->Description);
	
	// Copy the MAC address
	TmpAdInfo->MacAddressLen = IphAd->AddressLength;

	memcpy(TmpAdInfo->MacAddress, IphAd->Address, (MAX_MAC_ADDR_LENGTH<MAX_ADAPTER_ADDRESS_LENGTH)?  MAX_MAC_ADDR_LENGTH:MAX_ADAPTER_ADDRESS_LENGTH);

	// Calculate the number of IP addresses of this interface
	for(TmpAddrStr = &IphAd->IpAddressList, i = 0; TmpAddrStr != NULL; TmpAddrStr = TmpAddrStr->Next, i++)
	{
	}

	TmpAdInfo->pNetworkAddresses = NULL;

	FIXME("Adding the IPv4 addresses to the adapter %s...\n", TName);

	// Scan the addresses, convert them to addrinfo structures and put each
	// of them in the list

	for(TmpAddrStr = &IphAd->IpAddressList, i = 0; TmpAddrStr != NULL; TmpAddrStr = TmpAddrStr->Next)
	{
		PNPF_IF_ADDRESS_ITEM pItem, pCursor;
		
		if (inet_addr(TmpAddrStr->IpAddress.String)!= INADDR_NONE)
		{
			pItem = (PNPF_IF_ADDRESS_ITEM)GlobalAllocPtr(GPTR, sizeof(NPF_IF_ADDRESS_ITEM));
			if (pItem == NULL)
			{
				FIXME("Cannot allocate memory for an IPv4 address, skipping it\n");
				continue;
			}

			TmpAddr = (struct sockaddr_in *)&(pItem->Addr.IPAddress);
			TmpAddr->sin_addr.S_un.S_addr = inet_addr(TmpAddrStr->IpAddress.String);
			TmpAddr->sin_family = AF_INET; 
			TmpAddr = (struct sockaddr_in *)&(pItem->Addr.SubnetMask);
			TmpAddr->sin_addr.S_un.S_addr = inet_addr(TmpAddrStr->IpMask.String);
			TmpAddr->sin_family = AF_INET; 
			TmpAddr = (struct sockaddr_in *)&(pItem->Addr.Broadcast);
			TmpAddr->sin_addr.S_un.S_addr = 0xffffffff; // Consider 255.255.255.255 as broadcast address since IP Helper API doesn't provide information about it
			TmpAddr->sin_family = AF_INET;

			pItem->Next = NULL;

			if (TmpAdInfo->pNetworkAddresses == NULL)
			{
				TmpAdInfo->pNetworkAddresses = pItem;
			}

			else
			{
				pCursor = TmpAdInfo->pNetworkAddresses;
				while(pCursor->Next != NULL)
				{
					pCursor = pCursor->Next;
				}

				pCursor->Next = pItem;
			}
		}
	}

	//FIXME("Adding the IPv6 addresses to the adapter %s...\n", TName);

	// Now Add IPv6 Addresses

	//PacketAddIP6Addresses(TmpAdInfo);

	/*if(IphAd->Type == IF_TYPE_PPP || IphAd->Type == IF_TYPE_SLIP)
	{
		FIXME("Flagging the adapter as NDISWAN.\n");
		// NdisWan adapter
		TmpAdInfo->Flags = INFO_FLAG_NDISWAN_ADAPTER;
	}
        */
	
	// Update the AdaptersInfo list

	TmpAdInfo->Next = g_AdaptersInfoList;
	g_AdaptersInfoList = TmpAdInfo;

SkipAd:
        FIXME("recheck: TmpAdInfo->Name is %s\n", TmpAdInfo->Name);
        FIXME("recheck: g_AdaptersInfoList->Name is %s\n", wine_dbgstr_a(g_AdaptersInfoList->Name));
        FIXME("recheck: g_AdaptersInfoList->Description is %s\n", wine_dbgstr_a(g_AdaptersInfoList->Description));
	return TRUE;
}


static BOOLEAN PacketGetAdaptersIPH(void)
{
	PIP_ADAPTER_INFO AdList = NULL;
	PIP_ADAPTER_INFO TmpAd;
	ULONG OutBufLen=0;

	FIXME("PacketGetAdaptersIPH\n");

	// Find the size of the buffer filled by GetAdaptersInfo
	if(GetAdaptersInfo(AdList, &OutBufLen) == ERROR_NOT_SUPPORTED)
	{
		ERR("IP Helper API not supported on this system!\n");
		return FALSE;
	}

	FIXME("PacketGetAdaptersIPH: retrieved needed bytes for IPH\n");

	// Allocate the buffer
	AdList = GlobalAllocPtr(GMEM_MOVEABLE, OutBufLen);

	if (AdList == NULL) 
	{
		FIXME("PacketGetAdaptersIPH: GlobalAlloc Failed allocating the buffer for GetAdaptersInfo\n");
		return FALSE;
	}

	// Retrieve the adapters information using the IP helper API
	GetAdaptersInfo(AdList, &OutBufLen);

	FIXME("PacketGetAdaptersIPH: retrieved list from IPH. Adding adapters to the global list.\n");

	// Scan the list of adapters obtained from the IP helper API, create a
	// new ADAPTER_INFO
	// structure for every new adapter and put it in our global list
	for(TmpAd = AdList; TmpAd != NULL; TmpAd = TmpAd->Next)
	{
		PacketAddAdapterIPH(TmpAd);
	}

	(void)GlobalFreePtr(AdList);

	return TRUE;
}


LPPACKET PacketAllocatePacket(void)
{
    LPPACKET    lpPacket;
    FIXME("PacketAllocatePacket\n");
    lpPacket=(LPPACKET)GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT,sizeof(PACKET));
    FIXME("returned %p\n", lpPacket);
    if (lpPacket==NULL)
    {
        ERR("PacketAllocatePacket: GlobalAlloc Failed\n");
    }
    return lpPacket;
}


VOID PacketPopulateAdaptersInfoList(void)
{
	PADAPTER_INFO TAdInfo;
	PVOID Mem2;

	FIXME("PacketPopulateAdaptersInfoList\n");

	WaitForSingleObject(g_AdaptersInfoMutex, INFINITE);

	if(g_AdaptersInfoList)
	{
		// Free the old list
		TAdInfo = g_AdaptersInfoList;
		while(TAdInfo != NULL)
		{
			PNPF_IF_ADDRESS_ITEM pItem, pCursor;
			Mem2 = TAdInfo;

			pCursor = TAdInfo->pNetworkAddresses;
			TAdInfo = TAdInfo->Next;
			
			while(pCursor != NULL)
			{
				pItem = pCursor->Next;
				(void)GlobalFreePtr(pCursor);
				pCursor = pItem;
			}
			(void)GlobalFreePtr(Mem2);
		}
		
		g_AdaptersInfoList = NULL;
	}

	//
	// Fill the new list
	//
#ifdef NPF_ON_WINE
	if(!PacketGetAdaptersNPF())
	{
		// No info about adapters in the registry. (NDIS adapters, i.e.
		// exported by NPF)
		FIXME("PacketPopulateAdaptersInfoList: registry scan for adapters failed!\n");
	}

#endif 

#define HAVE_IPHELPER_API
#ifdef HAVE_IPHELPER_API
	if(!PacketGetAdaptersIPH())
	{
		// IP Helper API not present. We are under WinNT 4 or TCP/IP is
		// not installed
		FIXME("PacketPopulateAdaptersInfoList: failed to get adapters from the IP Helper API!\n");

	}
#endif //HAVE_IPHELPER_API

	ReleaseMutex(g_AdaptersInfoMutex);
	FIXME("PacketPopulateAdaptersInfoList end \n");
}

PADAPTER_INFO PacketFindAdInfo(PCHAR AdapterName)
{
        //this function should NOT acquire the g_AdaptersInfoMutex, since it
        //does return an ADAPTER_INFO structure
        PADAPTER_INFO TAdInfo;

        if (g_AdaptersInfoList == NULL)
        {
                TRACE("Repopulating the adapters info list...");
                PacketPopulateAdaptersInfoList();
        }

        TAdInfo = g_AdaptersInfoList;

        while(TAdInfo != NULL)
        {
                if(strcmp(TAdInfo->Name, AdapterName) == 0)
                {
                        TRACE("Found AdInfo for adapter %s", AdapterName);
                        break;
                }

                TAdInfo = TAdInfo->Next;
        }

        if (TAdInfo == NULL)
        {
                TRACE("NOT found AdInfo for adapter %s", AdapterName);
        }

        return TAdInfo;
}


BOOLEAN PacketGetAdapterNames(PTSTR pStr,PULONG  BufferSize)
{
	PADAPTER_INFO	TAdInfo;
	ULONG	SizeNeeded = 0;
	ULONG	SizeNames = 0;
	ULONG	SizeDesc;
	ULONG	OffDescriptions;
	FIXME("PacketGetAdapterNames pStr: %p, BufferSize=%u\n", pStr, *BufferSize);
	// Create the adapter information list
	//
	FIXME("Populating the adapter list...\n");
	PacketPopulateAdaptersInfoList();
	WaitForSingleObject(g_AdaptersInfoMutex, INFINITE);
	if(!g_AdaptersInfoList) 
	{
		ReleaseMutex(g_AdaptersInfoMutex);
		*BufferSize = 0;
		ERR("No adapters found in the system. Failing.\n");
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return FALSE;		// No adapters to return
	}
	// 
	// First scan of the list to calculate the offsets and check the sizes
	//
	for(TAdInfo = g_AdaptersInfoList; TAdInfo != NULL; TAdInfo = TAdInfo->Next)
	{
		if(TAdInfo->Flags != INFO_FLAG_DONT_EXPORT)
		{
			// Update the size variables
			SizeNeeded += (ULONG)strlen(TAdInfo->Name) + (ULONG)strlen(TAdInfo->Description) + 2;
			SizeNames += (ULONG)strlen(TAdInfo->Name) + 1;
		}
	}
	// Check that we don't overflow the buffer.
	// Note: 2 is the number of additional separators needed inside the list
	if(SizeNeeded + 2 > *BufferSize || pStr == NULL)
	{
		ReleaseMutex(g_AdaptersInfoMutex);
 		FIXME("PacketGetAdapterNames: input buffer too small, we need %u bytes\n", *BufferSize);
		*BufferSize = SizeNeeded + 2;  // Report the required size
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return FALSE;
	}

	OffDescriptions = SizeNames + 1;
	// 
	// Second scan of the list to copy the information
	//
	for(TAdInfo = g_AdaptersInfoList, SizeNames = 0, SizeDesc = 0; TAdInfo != NULL; TAdInfo = TAdInfo->Next)
	{
		if(TAdInfo->Flags != INFO_FLAG_DONT_EXPORT)
		{
			// Copy the data
			StringCchCopyA( ((PCHAR)pStr) + SizeNames, *BufferSize - SizeNames, TAdInfo->Name);
			StringCchCopyA( ((PCHAR)pStr) + OffDescriptions + SizeDesc, *BufferSize - OffDescriptions - SizeDesc, TAdInfo->Description);
			// Update the size variables
			SizeNames += (ULONG)strlen(TAdInfo->Name) + 1;
			SizeDesc += (ULONG)strlen(TAdInfo->Description) + 1;
		}
	}

	// Separate the two lists
	((PCHAR)pStr)[SizeNames] = 0;
	// End the list with a further \0
	((PCHAR)pStr)[SizeNeeded + 1] = 0;
	ReleaseMutex(g_AdaptersInfoMutex);

	return TRUE;
}


LPADAPTER PacketOpenAdapter(PCHAR AdapterNameWA)
{
        LPADAPTER lpAdapter = NULL;
	PCHAR AdapterNameA = NULL;
	BOOL bFreeAdapterNameA;
	
	DWORD dwLastError = ERROR_SUCCESS;
 
 	FIXME("PacketOpenAdapter: %s\n", AdapterNameWA);	
	
	FIXME("Packet DLL version %s, Driver version %s\n", PacketLibraryVersion, PacketDriverVersion); 

	if(AdapterNameWA[1]!=0)
	{ 
		//
		// ASCII
		//
		bFreeAdapterNameA = FALSE;
		AdapterNameA = AdapterNameWA;
	} 
	else 
	{	
		//
		// Unicode
		//
		size_t bufferSize = strlenW((PWCHAR)AdapterNameWA) + 1;
		
                ERR("check if AdapterName is really Unicode!!\n\n");
		AdapterNameA = GlobalAllocPtr(GPTR, bufferSize);
		if (AdapterNameA == NULL)
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			return NULL;
		}
		StringCchPrintfA(AdapterNameA, bufferSize, "%ws", (PWCHAR)AdapterNameWA);
		bFreeAdapterNameA = TRUE;
	}
	do
	{
		//
		// This is the only code executed on NT4
		//
		// Windows NT4 does not have support for the various nifty
		// adapters supported from 2000 on (airpcap, ndiswan, npfim...)
		// so we just skip all the magic of the global adapter list, 
		// and try to open the adapter with PacketOpenAdapterNPF at
		// the end of this big function!
		//
		FIXME("Normal NPF adapter, trying to open it...\n");
		lpAdapter = PacketOpenAdapterNPF(AdapterNameA);
		if (lpAdapter == NULL)
		{
			dwLastError = GetLastError();
		}
	}while(FALSE);
	if (bFreeAdapterNameA) GlobalFree(AdapterNameA);

	if (dwLastError != ERROR_SUCCESS)
	{
		SetLastError(dwLastError);
		return NULL;
	}
	else
	{
                lpAdapter->hFile = pcap_open_live(lpAdapter->Name, 65536, 1, 1000, errbuf);
                FIXME("Dirty hack! pcap_t is: %p\n", lpAdapter->hFile);
		return lpAdapter;
	}
}

VOID PacketCloseAdapter (LPADAPTER lpAdapter)
{
        FIXME("Packet32: PacketCloseAdapter lpAdapter: %p\n", lpAdapter);

        // close the capture handle
        CloseHandle (lpAdapter->hFile);

        // close the read event
        CloseHandle (lpAdapter->ReadEvent);
        (void)GlobalFreePtr(lpAdapter);
        lpAdapter = NULL;
}

PCHAR PacketGetDriverVersion(void)
{
        FIXME("PacketGetDriverVersion: %s\n", PacketDriverVersion);
        return PacketDriverVersion;
}

PCHAR PacketGetVersion(void)
{
        FIXME("PacketGetVersion: %s\n", PacketLibraryVersion);
        return PacketLibraryVersion;
}

BOOLEAN PacketSetHwFilter(LPADAPTER  AdapterObject,ULONG Filter)
{
        FIXME("stub AdapterObject: %p, Filter: %u\n", AdapterObject, Filter);
        return TRUE;
}

BOOLEAN PacketSetBuff(LPADAPTER AdapterObject,int dim)
{
        FIXME("Stub AdapterObject: %p, dim: %d\n", AdapterObject, dim);
        return TRUE;
}

VOID PacketInitPacket(LPPACKET lpPacket,PVOID Buffer,UINT Length)
{
        FIXME("Stub lpPacket: %p, Buffer: %p, Length: %u\n", lpPacket, Buffer, Length);
        lpPacket->Buffer = Buffer;
        lpPacket->Length = Length;
        lpPacket->ulBytesReceived = 0;
        lpPacket->bIoComplete = FALSE;
}

BOOLEAN PacketReceivePacket(LPADAPTER AdapterObject,LPPACKET lpPacket,BOOLEAN Sync)
{
        struct pcap_pkthdr *header;
        const u_char *pkt_data;
        u_char *Packet_data = lpPacket->Buffer;
        u_char *Packet_header= lpPacket->Buffer;
        int res=0;
        int i;

        ((struct bpf_hdr *)lpPacket->Buffer)->bh_hdrlen = 20;
        for (i=0; i<20; i++)
                Packet_data++; 

        FIXME("Stub AdapterObject: %p, lpPacket: %p, Sync: %d\n", AdapterObject, lpPacket, Sync);
        FIXME("AdapterObject->pcap_t is %p\n", AdapterObject->hFile);

        res = pcap_next_ex( AdapterObject->hFile, &header, &pkt_data);
        if ( res < 0) return FALSE;
        if ( res >= 0)
        {
                memcpy(Packet_header, header, sizeof(*header)); 
                memcpy(Packet_data, pkt_data, header->len);
                lpPacket->ulBytesReceived = header->len;
                FIXME("header is %d\n", sizeof(*header));
        }


        FIXME("lpPacket->Length is %u\n", lpPacket->Length);
        FIXME("lpPacket->Buffer is %p\n", lpPacket->Buffer);
        FIXME("lpPacket->ulBytesReceived is %u\n", lpPacket->ulBytesReceived);

        return TRUE;
}

BOOLEAN PacketSendPacket(LPADAPTER AdapterObject,LPPACKET lpPacket,BOOLEAN
Sync)
{
        FIXME("Stub AdapterObject: %p, lpPacket: %p, Sync: %d\n", AdapterObject, lpPacket, Sync);
        return TRUE;
}

BOOLEAN PacketSetReadTimeout(LPADAPTER AdapterObject,int timeout)
{
        FIXME("Stub AdapterObject: %p, timeout: %d\n", AdapterObject, timeout);
        return TRUE;
}

BOOLEAN PacketSetNumWrites(LPADAPTER AdapterObject,int nwrites)
{
        FIXME("Stub AdapterObject: %p, nwrites: %d\n", AdapterObject, nwrites);
        return TRUE;
}

VOID PacketFreePacket(LPPACKET lpPacket)

{
    FIXME("lpPacket: %p\n", lpPacket);
    (void)GlobalFreePtr(lpPacket);
}

BOOLEAN PacketGetNetType(LPADAPTER AdapterObject, NetType *type)
{
        PADAPTER_INFO TAdInfo;
        BOOLEAN ret;

        FIXME("AdapterObject: %p, type: %p\n", AdapterObject, type);
        WaitForSingleObject(g_AdaptersInfoMutex, INFINITE);
        // Find the PADAPTER_INFO structure associated with this adapter 
        TAdInfo = PacketFindAdInfo(AdapterObject->Name);

        if(TAdInfo != NULL)
        {
                TRACE("Adapter found");
                // Copy the data
                memcpy(type, &(TAdInfo->LinkLayer), sizeof(struct NetType));
                ret = TRUE;
        }
        else
        {
                TRACE("PacketGetNetType: Adapter not found");
                ret =  FALSE;
        }

        TRACE("%u, %llu\n", type->LinkType, type->LinkSpeed);

        ReleaseMutex(g_AdaptersInfoMutex);

        return ret;
}

BOOLEAN PacketSetMinToCopy(LPADAPTER AdapterObject,int nbytes)
{
        FIXME("AdapterObject: %p, nbytes: %d\n", AdapterObject, nbytes);
        // pcap_setmintocopy
        return TRUE;
}

static PCHAR WChar2SChar(PWCHAR string)
{
        PCHAR TmpStr;
        TmpStr = (CHAR*) GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT, (DWORD)(lstrlenW(string)+2));

        // Conver to ASCII
        WideCharToMultiByte( CP_ACP, 0, string, -1, TmpStr, (DWORD)(lstrlenW(string)+2), NULL, NULL);

        return TmpStr;
}


BOOLEAN PacketGetNetInfoEx(PCHAR AdapterName, npf_if_addr* buffer, PLONG NEntries)
{
	PADAPTER_INFO TAdInfo;
	PCHAR Tname;
	BOOLEAN Res, FreeBuff;

        FIXME("AdapterName: %s, buffer: %p, NEntries: %p \n", AdapterName, buffer, NEntries);

	// Provide conversion for backward compatibility
	if(AdapterName[1] != 0)
	{ //ASCII
		Tname = AdapterName;
		FreeBuff = FALSE;
	}
	else
	{
		Tname = WChar2SChar((PWCHAR)AdapterName);
		FreeBuff = TRUE;
	}
	FIXME("Should Update the information about this adapter.\n");

	WaitForSingleObject(g_AdaptersInfoMutex, INFINITE);
	// Find the PADAPTER_INFO structure associated with this adapter 
	TAdInfo = PacketFindAdInfo(Tname);
	if(TAdInfo != NULL)
	{
		LONG numEntries = 0, i;
		PNPF_IF_ADDRESS_ITEM pCursor;

		pCursor = TAdInfo->pNetworkAddresses;

		while(pCursor != NULL)
		{
			numEntries ++;
			pCursor = pCursor->Next;
		}
		if (numEntries < *NEntries)
		{
			*NEntries = numEntries;
		}

		pCursor = TAdInfo->pNetworkAddresses;
		for (i = 0; (i < *NEntries) && (pCursor != NULL); i++)
		{
			buffer[i] = pCursor->Addr;
			pCursor = pCursor->Next;
		}

		Res = TRUE;
	}
	else
	{
		Res = FALSE;
	}
	ReleaseMutex(g_AdaptersInfoMutex);
	if(FreeBuff) (void)GlobalFreePtr(Tname);
	return Res;
}

BOOLEAN PacketSetBpf(LPADAPTER AdapterObject, struct bpf_program *fp)
{
        FIXME(" AdapterObject: %p, fp: %p \n", AdapterObject, fp);
        // pcap_setfilter(pcap_t *p, struct bpf_program *fp);
        return TRUE;
}
