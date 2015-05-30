#闪迅客户端


[Bug 30208](https://code.google.com/p/wine-winpcap-wrapper/issues/detail?id=0208) - NKSetup (Shan Xun 802.1x client) infinite loop while installing


Workaround:

1. copy native netcfgx.dll

2. regsvr32 netcfgx.dll

3. import the network-stub-1.reg

http://wine-winpcap-wrapper.googlecode.com/files/network-stub-1.reg