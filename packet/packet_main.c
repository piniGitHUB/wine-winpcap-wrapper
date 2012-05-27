/*
 * packet.dll
 *
 * Generated from packet.dll by winedump.
 *
 * DO NOT SUBMIT GENERATED DLLS FOR INCLUSION INTO WINE!
 *
 */


#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "wine/debug.h"

#include "packet32.h"
#include "stdio.h"
#include "wine/unicode.h"

WINE_DEFAULT_DEBUG_CHANNEL(packet);


char PacketLibraryVersion[64] = "4.1.0.2001";
char PacketDriverVersion[64] = "4.1.0.2001";

volatile LONG g_DynamicLibrariesLoaded = 0;
HANDLE g_DynamicLibrariesMutex;
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
		TRACE("OidData should be zero? %d \n", GlobalFreePtr(OidData));
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
			TRACE("%d\n", GlobalFreePtr(lpAdapter));
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
	TRACE("%d\n",GlobalFreePtr(lpAdapter));
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

	TRACE("%d\n",GlobalFreePtr(AdList));

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


VOID PacketLoadLibrariesDynamically(void)
{
        HMODULE IPHMod;

        g_DynamicLibrariesLoaded++;

        if(g_DynamicLibrariesLoaded != 1)
        {
                ReleaseMutex(g_DynamicLibrariesMutex);
                FIXME("PacketLoadLibrariesDynamically already done!\n");
                return;
        }

        IPHMod = GetModuleHandleA("Iphlpapi");
        if (IPHMod != NULL)
        {
                g_GetAdaptersAddressesPointer = (GAAHandler) GetProcAddress(IPHMod ,"GetAdaptersAddresses");
        }

        ReleaseMutex(g_DynamicLibrariesMutex);
        return;
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
				TRACE("%d\n",GlobalFreePtr(pCursor));
				pCursor = pItem;
			}
			TRACE("%d\n",GlobalFreePtr(Mem2));
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

BOOLEAN PacketGetAdapterNames(PTSTR pStr,PULONG  BufferSize)
{
	PADAPTER_INFO	TAdInfo;
	ULONG	SizeNeeded = 0;
	ULONG	SizeNames = 0;
	ULONG	SizeDesc;
	ULONG	OffDescriptions;
	FIXME("PacketGetAdapterNames\n");
	FIXME("Packet DLL version %s, Driver version %s\n", PacketLibraryVersion, PacketDriverVersion);
	FIXME("PacketGetAdapterNames: BufferSize=%u\n", *BufferSize);
	// Check the presence on some libraries we rely on, and load them if we
	// found them
	//f
	PacketLoadLibrariesDynamically();
	//d
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

	PacketLoadLibrariesDynamically();
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
		return lpAdapter;
	}
}

VOID PacketCloseAdapter (LPADAPTER lpAdapter)
{
        FIXME("Packet32: PacketCloseAdapter\n");

        // close the capture handle
        CloseHandle (lpAdapter->hFile);

        // close the read event
        CloseHandle (lpAdapter->ReadEvent);
        TRACE("%d\n",GlobalFreePtr (lpAdapter));
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
