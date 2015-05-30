# Proof of concept: Running mentohust.exe on Wine

# Introduction #

Mentohust `[1]` is an open source and cross-platform alternative of Ruijie 802.1x authentication client.

The Linux version of Mentohust is base on libpcap, and the Win32 version is base on winpcap. Running Mentohust.exe on Wine doesn't make so much sense, because it is already open source and cross-platform. However, there are other network authentication clients based on winpcap but not open source and or cross-platform `[2]`, if they can run on Wine then it is very useful.

I've make a proof-of-concept, show that the Windows version of mentohust could work on Wine with André H's wpcap wrapper `[3]`

# Steps #

  1. Install latest Wine
  1. Download the Windows version of mentohust `[4]` `[I]`
  1. Download wpcap.dll.so from `[3]`, copy to /usr/lib/wine/wpcap.dll.so
  1. Copy mfc90.dll to the same directory of mentohust-mfc90.exe
  1. start mentohust-mfc90.exe as root `[II]` `[III]`
  1. mentohust-mfc90 should work as the same as on Windows. However, for people who has no network environment, it is difficult to confirm mentohust-mfc90 is really working, but we still have some alternative methods:

> a) run mentohust-mfc90 in a virtual machine, which has a interface bridged to the host machine, then use tcpdump or wireshark to monitor the interface on host machine, we'll get the package in the host.

> b) run mentohust-mfc90 in a virtual machine, at the same time run pyh3c-server `[5]` on the host machine. Also, bridge the guest interface and the host interface. mentohust will discovered the host machine as a authentication server, pyh3c-server should receive from mentohust and send package back. After that mentohust will try to send username to the server. `[IV]`

Any comment is welcome.


`[I]` On Windows, an interface name looks like `/Device/Blabla_{xxxx-xxxx-xxxxxxxx-xxxxxxxxxxxx}`, the original version of mentohust will check the length of the interface name, if it is shorter than 38 characters then mentohust will report an error and refuse to continue.

However, on Linux, the length of interface name could not be more then IFNAMSIZ which is 16. I've modified the source code of mentohust to avoid checking for interface name length, and recompiled with VS2008. The modified source code is here: `[6]`

`[II]` The interfaces listed in mentohust is empty, this has been reported as a libpcap bug (feature request), see `[7]`

`[III]` Also could use setcap to avoid root

`[IV]` pyh3c-server is an open source H3C 802.1x authentication server, based on reverse engineering. Currently we have no open source Ruijie 802.1x authentication server, so I use pyh3c-server as a alternative, it is just a workaround. Since H3C protocol is not exactly the same as Ruijie protocol, the mentohust client will not pass the authentication on the pyh3c-server, but at least it can discover the server and send out the username, and the server does receive data from the client, I think it is enough for our proof-of-concept.




`[1]` http://code.google.com/p/mentohust/

`[2]` http://code.google.com/p/wine-winpcap-wrapper/wiki/WinpcapBasedAuthClients (keeping updating)

`[3]` http://dawncrow.de/wine/wpcap.html

`[4]` http://study-codes-by-fracting.googlecode.com/files/mentohust-mfc90.exe

`[5]` https://github.com/houqp/pyh3c

`[6]` http://study-codes-by-fracting.googlecode.com/files/mentohust-win-src.zip

`[7]` http://sourceforge.net/tracker/?func=detail&aid=3502435&group_id=53067&atid=469580