/*
 * WPcap.dll Proxy.
 *
 * Copyright 2011 AndrÃ© Hentschel
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "config.h"

#include <stdarg.h>
#include <pcap/pcap.h>
#include "winsock2.h"
#include "windef.h"
#include "winbase.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(wpcap);
WINE_DECLARE_DEBUG_CHANNEL(winediag);

VOID CDECL wine_pcap_breakloop(pcap_t *p)
{
    TRACE("(%p)\n", p);
    return pcap_breakloop(p);
}

VOID CDECL wine_pcap_close(pcap_t *p)
{
    TRACE("(%p)\n", p);
    pcap_close(p);
}

INT CDECL wine_pcap_compile(pcap_t *p, struct bpf_program *program,
                            CONST CHAR *buf, INT optimize, UINT mask)
{
    TRACE("(%p)\n", p);
    return pcap_compile(p, program, buf, optimize, mask);
}

INT CDECL wine_pcap_datalink(pcap_t *p)
{
    TRACE("(%p)\n", p);
    return pcap_datalink(p);
}

INT CDECL wine_pcap_datalink_name_to_val(CONST CHAR *name)
{
    TRACE("(%s)\n", debugstr_a(name));
    return pcap_datalink_name_to_val(name);
}

CONST CHAR *CDECL wine_pcap_datalink_val_to_description(INT dlt)
{
    TRACE("(%i)\n", dlt);
    return pcap_datalink_val_to_description(dlt);
}

CONST CHAR *CDECL wine_pcap_datalink_val_to_name(INT dlt)
{
    TRACE("(%i)\n", dlt);
    return pcap_datalink_val_to_name(dlt);
}

INT CDECL wine_pcap_dispatch(pcap_t *p, INT cnt, pcap_handler callback, UCHAR *user)
{
    TRACE("(%p %i %p %p)\n", p, cnt, callback, user);
    return pcap_dispatch(p, cnt, callback, user);
}

INT CDECL wine_pcap_findalldevs(pcap_if_t **alldevsp, CHAR *errbuf)
{
    INT ret;
    TRACE("(%p %p)\n", alldevsp, errbuf);
    ret = pcap_findalldevs(alldevsp,errbuf);
    if(alldevsp && !*alldevsp)
        ERR_(winediag)("Failed to access raw network (pcap), this requires special permissions.\n");
    return ret;
}

VOID CDECL wine_pcap_freealldevs(pcap_if_t *alldevs)
{
    TRACE("(%p)\n", alldevs);
    pcap_freealldevs(alldevs);
}

VOID CDECL wine_pcap_freecode(struct bpf_program *fp)
{
    TRACE("(%p)\n", fp);
    return pcap_freecode(fp);
}

CHAR* CDECL wine_pcap_geterr(pcap_t *p)
{
    TRACE("(%p)\n", p);
    return pcap_geterr(p);
}

INT CDECL wine_pcap_getnonblock(pcap_t *p, CHAR *errbuf)
{
    TRACE("(%p %p)\n", p, errbuf);
    return pcap_getnonblock(p, errbuf);
}

CONST CHAR *CDECL wine_pcap_lib_version(VOID)
{
    CONST CHAR *ret;
    ret = pcap_lib_version();
    TRACE("%s\n", debugstr_a(ret));
    return ret;
}

INT CDECL wine_pcap_list_datalinks(pcap_t *p, INT **dlt_buffer)
{
    TRACE("(%p %p)\n", p, dlt_buffer);
    return pcap_list_datalinks(p, dlt_buffer);
}

CHAR* CDECL wine_pcap_lookupdev(CHAR *errbuf)
{
    TRACE("(%p)\n", errbuf);
    return pcap_lookupdev(errbuf);
}

INT CDECL wine_pcap_lookupnet(CONST CHAR *device, UINT *netp, UINT *maskp, CHAR *errbuf)
{
    TRACE("(%p %p %p %p)\n", device, netp, maskp, errbuf);
    return pcap_lookupnet(device, netp, maskp, errbuf);
}

INT CDECL wine_pcap_loop(pcap_t *p, INT cnt, pcap_handler callback, UCHAR *user)
{
    TRACE("(%p %i %p %p)\n", p, cnt, callback, user);
    return pcap_loop(p, cnt, callback, user);
}

INT CDECL wine_pcap_major_version(pcap_t *p)
{
    TRACE("(%p)\n", p);
    return pcap_major_version(p);
}

INT CDECL wine_pcap_minor_version(pcap_t *p)
{
    TRACE("(%p)\n", p);
    return pcap_minor_version(p);
}

CONST UCHAR* CDECL wine_pcap_next(pcap_t *p, struct pcap_pkthdr *h)
{
    TRACE("(%p %p)\n", p, h);
    return pcap_next(p, h);
}

INT CDECL wine_pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header, CONST UCHAR **pkt_data)
{
    TRACE("(%p %p %p)\n", p, pkt_header, pkt_data);
    return pcap_next_ex(p,pkt_header,pkt_data);
}

pcap_t * CDECL wine_pcap_open_live(CONST CHAR *source, INT snaplen,
                                   INT promisc , INT to_ms , CHAR *errbuf)
{
    TRACE("(%p %i %i %i %p)\n", source, snaplen, promisc, to_ms, errbuf);
    FIXME("source is %s\n", source);
    //source = source + 12;
    //FIXME("new source is %s\n", source);
    return pcap_open_live(source, snaplen, promisc, to_ms, errbuf);
}

INT CDECL wine_pcap_sendpacket(pcap_t *p, CONST UCHAR *buf, INT size)
{
    TRACE("(%p %p %i)\n", p, buf, size);
    return pcap_sendpacket(p, buf, size);
}

INT CDECL wine_pcap_set_datalink(pcap_t *p, INT dlt)
{
    TRACE("(%p %i)\n", p, dlt);
    return pcap_set_datalink(p, dlt);
}

INT CDECL wine_pcap_setbuff(pcap_t * p, INT dim)
{
    FIXME("(%p %i) stub\n", p, dim);
    return 0;
}

INT CDECL wine_pcap_setfilter(pcap_t *p, struct bpf_program *fp)
{
    TRACE("(%p %p)\n", p, fp);
    return pcap_setfilter(p, fp);
}

INT CDECL wine_pcap_setnonblock(pcap_t *p, INT nonblock, CHAR *errbuf)
{
    TRACE("(%p %i %p)\n", p, nonblock, errbuf);
    return pcap_setnonblock(p, nonblock, errbuf);
}

INT CDECL wine_pcap_snapshot(pcap_t *p)
{
    TRACE("(%p)\n", p);
    return pcap_snapshot(p);
}

INT CDECL wine_pcap_stats(pcap_t *p, struct pcap_stat *ps)
{
    TRACE("(%p %p)\n", p, ps);
    return pcap_stats(p, ps);
}

INT CDECL wine_wsockinit(VOID)
{
    WSADATA wsadata;
    TRACE("()\n");
    if (WSAStartup(MAKEWORD(1,1), &wsadata)) return -1;
    return 0;
}

pcap_dumper_t * CDECL wine_pcap_dump_open(pcap_t *p, const char *fname)
{
    TRACE("(%p %s)\n", p, fname);
    return pcap_dump_open(p, fname);
}

void CDECL wine_pcap_dump(u_char *user, struct pcap_pkthdr *h, u_char *sp)
{
    TRACE("(%s %p %s)\n", user, h, sp);
    pcap_dump(user, h, sp);
}
