# Generated from packet.dll by winedump

1 cdecl PacketAllocatePacket()
2 cdecl PacketCloseAdapter(ptr)
3 cdecl PacketFreePacket(ptr)
4 cdecl PacketGetAdapterNames(ptr ptr)
5 stub PacketGetAirPcapHandle
6 cdecl PacketGetDriverVersion()
7 cdecl PacketGetNetInfoEx(str ptr ptr)
8 cdecl PacketGetNetType(ptr ptr)
9 stub PacketGetReadEvent
10 stub PacketGetStats
11 stub PacketGetStatsEx
12 cdecl PacketGetVersion()
13 cdecl PacketInitPacket(ptr ptr long)
14 stub PacketIsDumpEnded
15 stub PacketLibraryVersion
16 cdecl PacketOpenAdapter(str)
17 cdecl PacketReceivePacket(ptr ptr long)
18 cdecl PacketRequest(ptr long ptr)
19 cdecl PacketSendPacket(ptr ptr long)
20 stub PacketSendPackets
21 cdecl PacketSetBpf(ptr ptr)
22 cdecl PacketSetBuff(ptr long)
23 stub PacketSetDumpLimits
24 stub PacketSetDumpName
25 cdecl PacketSetHwFilter(ptr long)
26 stub PacketSetLoopbackBehavior
27 cdecl PacketSetMinToCopy(ptr long)
28 stub PacketSetMode
29 cdecl PacketSetNumWrites(ptr long)
30 cdecl PacketSetReadTimeout(ptr long)
31 stub PacketSetSnapLen
32 stub PacketStopDriver
