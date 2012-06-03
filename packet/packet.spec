# Generated from packet.dll by winedump

1 stdcall PacketAllocatePacket()
2 stdcall PacketCloseAdapter(ptr)
3 stdcall PacketFreePacket(ptr)
4 stdcall PacketGetAdapterNames(ptr ptr)
5 stub PacketGetAirPcapHandle
6 stdcall PacketGetDriverVersion()
7 stdcall PacketGetNetInfoEx(ptr ptr ptr)
8 stdcall PacketGetNetType(ptr ptr)
9 stub PacketGetReadEvent
10 stub PacketGetStats
11 stub PacketGetStatsEx
12 stdcall PacketGetVersion()
13 stdcall PacketInitPacket(ptr ptr long)
14 stub PacketIsDumpEnded
15 stub PacketLibraryVersion
16 stdcall PacketOpenAdapter(ptr)
17 stdcall PacketReceivePacket(ptr ptr long)
18 stdcall PacketRequest(ptr long ptr)
19 stdcall PacketSendPacket(ptr ptr long)
20 stub PacketSendPackets
21 stdcall PacketSetBpf(ptr ptr)
22 stdcall PacketSetBuff(ptr long)
23 stub PacketSetDumpLimits
24 stub PacketSetDumpName
25 stdcall PacketSetHwFilter(ptr long)
26 stub PacketSetLoopbackBehavior
27 stdcall PacketSetMinToCopy(ptr long)
28 stub PacketSetMode
29 stdcall PacketSetNumWrites(ptr long)
30 stdcall PacketSetReadTimeout(ptr long)
31 stub PacketSetSnapLen
32 stub PacketStopDriver
