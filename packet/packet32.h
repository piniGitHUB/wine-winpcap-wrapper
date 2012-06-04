typedef LPSTR           PTSTR,       LPTSTR;

#include "sockstorage.h"
#include "winsock2.h"
#include "iphlpapi.h"

#define GlobalPtrHandle(lp)                     ((HGLOBAL)GlobalHandle(lp))
#define GlobalUnlockPtr(lp) GlobalUnlock(GlobalPtrHandle(lp))

#define GlobalAllocPtr(flags, cb)               (GlobalLock(GlobalAlloc((flags), (cb))))
#define GlobalFreePtr(lp)                       (GlobalUnlockPtr(lp), (BOOL)(ULONG_PTR)GlobalFree(GlobalPtrHandle(lp)))

typedef struct _PACKET {
        HANDLE       hEvent;
        OVERLAPPED   OverLapped;
        PVOID        Buffer;
        UINT         Length;
        DWORD        ulBytesReceived;
        BOOLEAN      bIoComplete;
}  PACKET, *LPPACKET;

#define        MAX_LINK_NAME_LENGTH     64
#define ADAPTER_NAME_LENGTH 256 + 12

typedef struct WAN_ADAPTER_INT WAN_ADAPTER; ///< Describes an opened wan (dialup, VPN...) network adapter using the NetMon API
typedef WAN_ADAPTER *PWAN_ADAPTER;

typedef struct _ADAPTER  {
        HANDLE hFile;
        CHAR  SymbolicLink[MAX_LINK_NAME_LENGTH];
        int NumWrites;
        HANDLE ReadEvent;
        UINT ReadTimeOut;
        CHAR Name[ADAPTER_NAME_LENGTH];
        PWAN_ADAPTER pWanAdapter;
        UINT Flags;
#ifdef HAVE_AIRPCAP_API
        PAirpcapHandle  AirpcapAd;
#endif // HAVE_AIRPCAP_API

#ifdef HAVE_NPFIM_API
        void* NpfImHandle;
#endif // HAVE_NPFIM_API

#ifdef HAVE_DAG_API
        dagc_t *pDagCard;
        PCHAR DagBuffer;
        struct timeval DagReadTimeout;
        unsigned DagFcsLen;
        DWORD DagFastProcess;
#endif // HAVE_DAG_API
}  ADAPTER, *LPADAPTER;


#define ADAPTER_NAME_LENGTH 256 + 12
#define ADAPTER_DESC_LENGTH 128
#define MAX_MAC_ADDR_LENGTH 8 

typedef struct NetType
{
        UINT LinkType;
        ULONGLONG LinkSpeed;
}NetType;

typedef struct npf_if_addr {
        struct sockaddr_storage IPAddress;
        struct sockaddr_storage SubnetMask;
        struct sockaddr_storage Broadcast;
}npf_if_addr;

typedef struct _NPF_IF_ADDRESS_ITEM
{
        npf_if_addr Addr;
        struct _NPF_IF_ADDRESS_ITEM *Next;
} NPF_IF_ADDRESS_ITEM, *PNPF_IF_ADDRESS_ITEM;

typedef struct _ADAPTER_INFO
{
        struct _ADAPTER_INFO *Next;
        CHAR Name[ADAPTER_NAME_LENGTH + 1];
        CHAR Description[ADAPTER_DESC_LENGTH + 1];
        UINT MacAddressLen;
        UCHAR MacAddress[MAX_MAC_ADDR_LENGTH];
        NetType LinkLayer;
        PNPF_IF_ADDRESS_ITEM pNetworkAddresses;
        UINT Flags;
}
ADAPTER_INFO, *PADAPTER_INFO;

#define INFO_FLAG_DONT_EXPORT           8 
#define MAX_WINPCAP_KEY_CHARS 512
//#define NPF_DRIVER_NAME "NPF"
#define NPF_DRIVER_NAME   ""
//#define NPF_DRIVER_COMPLETE_DEVICE_PREFIX  "\\Device\\" NPF_DRIVER_NAME "_"
#define NPF_DRIVER_COMPLETE_DEVICE_PREFIX       ""

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

#define INFO_FLAG_NDIS_ADAPTER          0
#define BIOCSETEVENTHANDLE 7920

struct _PACKET_OID_DATA {
    ULONG Oid;
    ULONG Length;
    UCHAR Data[1];
};
typedef struct _PACKET_OID_DATA PACKET_OID_DATA, *PPACKET_OID_DATA;

// OID definitions
#define OID_GEN_CURRENT_LOOKAHEAD 0x0001010F
#define OID_GEN_MAXIMUM_LOOKAHEAD 0x00010105 // from reactos
#define OID_GEN_MEDIA_CONNECT_STATUS 0x00010114
#define OID_802_3_PERMANENT_ADDRESS 0x01010101 
#define OID_802_3_CURRENT_ADDRESS 0x01010102


#define  BIOCSETOID 2147483648
#define  BIOCQUERYOID 2147483652

#ifdef NO_PCAP_HEADER
struct bpf_program
{
        UINT bf_len;
        struct bpf_insn *bf_insns;
};

struct bpf_insn
{
        USHORT  code;
        UCHAR   jt;
        UCHAR   jf;
        int k;
};
#endif

struct bpf_hdr
{
        struct timeval  bh_tstamp;      ///< The timestamp associated with the
        UINT    bh_caplen;                      ///< Length of captured portion.
        UINT    bh_datalen;                     ///< Original length of packet
        USHORT          bh_hdrlen;              ///< Length of bpf header (this
};

