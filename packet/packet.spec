# Generated from packet.dll by winedump

1 stdcall PacketAllocatePacket()
2 stdcall PacketCloseAdapter(ptr)
3 stub PacketFreePacket
4 stdcall PacketGetAdapterNames(ptr ptr)
5 stub PacketGetAirPcapHandle
6 stdcall PacketGetDriverVersion()
7 stub PacketGetNetInfoEx
8 stub PacketGetNetType
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
21 stub PacketSetBpf
22 stdcall PacketSetBuff(ptr long)
23 stub PacketSetDumpLimits
24 stub PacketSetDumpName
25 stdcall PacketSetHwFilter(ptr long)
26 stub PacketSetLoopbackBehavior
27 stub PacketSetMinToCopy
28 stub PacketSetMode
29 stub PacketSetNumWrites
30 stub PacketSetReadTimeout
31 stub PacketSetSnapLen
32 stub PacketStopDriver
