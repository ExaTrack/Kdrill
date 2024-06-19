# Kdrill

Kdrill is a tool to analyze the kernel land of Windows 64b systems (tested from Windows 7 to Windows 11). Its main objective is to assess if the kernel is compromised by a rootkit.

The code is compatible for python2/3 without dependencies and can perfom checks without Microsoft symbols or Internet connectivity.

For live memory/kernel analysis, the `Winpmem` driver is used and `Kdrill` interfaces itself with the driver. KDrill can also analyze Full crash dumps and Kernel crash dumps (mainly stored in `C:\Windows\MEMORY.DMP`) and a fucked version of AFF4 dumps (zip, but not zipped).

`Kdrill` accesses the physical memory and decodes/re-builds the OS internals structures to explore them, and to verify their intergrity.

The following checks are performed:
- Loaded modules list
- Drivers in memory code (compared to on-disk version)
- Callbacks of kernel objects and internal ntoskrnl lists
- PlugAndPlay tree and filters
- FltMgr callbacks
- KTimers DPC functions
- IRP driver's tables
- Driver signing global variables avec callbacks
- NDIS filters and callbacks
- NetIO/FwpkCLNT filtering dispatch
- Devices and their attached device objects
- IDT entries
- PatchGuard initialization and state

## Internals

Kdrill retrieves all kernel structures offsets automatically and builds a specific mapping at each execution. So it doesn't need symbols or Internet connectivity to resolve them (:wink: disconnected networks).

Most checks verify if the callback or pointed function is in a driver and if the driver is inside a "trust list" I made totally random. I strongly recommend you to check if those drivers are signed (by a trusted signer) ;)

However, for integrity drivers checks, you will need to have an Internet access to download Microsoft binaries from MS servers in order to diff them. If you already have them in `c:\symbols` it's fine too :)

## Rootkits examples

Some examples of rootkits detections (not all triggers, juste intersting finds).

### Winnti

Winnti replaces functions pointers in the NDIS callback of TCPIP. With the `cndis` command we can identify it:

```
#>> cndis
 [*] Checking NDIS Firewall layers
  [*] List from fffffa80033d3d70
    Driver      : pacer.sys
    GUID        : {B5F4D659-7DAA-4565-8E41-BE220ED60542}
    Description : QoS Packet Scheduler
    Driver      : wfplwf.sys
    GUID        : {B70D6460-3635-4D42-B866-B8AB1A24454C}
    Description : WFP LightWeight Filter
 [*] Checking NDIS Protocol layers
  [*] List from fffffa8002a71a60
    Name : NDIS6FW
  Callback fffff88003329e50 -> c:\users\toto\appdata\local\temp\tmp1ec3.tmp (not in white list) SUSPICIOUS
  Callback fffff88003329e50 -> c:\users\toto\appdata\local\temp\tmp1ec3.tmp (not in white list) SUSPICIOUS
[...]
    Name : NDISWAN
    Name : WANARPV6
    Name : WANARP
    Name : TCPIP6TUNNEL
    Name : TCPIPTUNNEL
    Name : TCPIP6
    Name : TCPIP
  Callback fffff8800332a660 -> c:\users\toto\appdata\local\temp\tmp1ec3.tmp (not in white list) SUSPICIOUS
  Callback fffff8800332a810 -> c:\users\toto\appdata\local\temp\tmp1ec3.tmp (not in white list) SUSPICIOUS
```

### Turla/Uroburos

Callback inside PspCreateProcessNotifyRoutine:
```
#>> ccb
  [*] Checking \Callback\TcpConnectionCallbackTemp : 0xfffffa8002f38360
  [*] Checking \Callback\TcpTimerStarvationCallbackTemp : 0xfffffa8004dfd640
  [*] Checking \Callback\LicensingData : 0xfffffa80024bc2f0
  [*] Checking \Callback\LLTDCallbackRspndr0006000006000000 : 0xfffffa80048713a0
[...]
 [*] PspLoadImageNotifyRoutine
 [*] PspCreateProcessNotifyRoutine
  Callback fffffa8004bc2874 -> SUSPICIOUS ***Unknown*** 48 89 5c 24 08 57 48 81 ec 30 01 00 00 48 8b fa
```

This rootkit also inserts a network IO filtering in FwpkCLNT:
```
#>> cnetio
  [*] FwpkCLNT/NetIo Callouts (callbacks) : fffffa8004965000 (4790)
  Callback fffffa8004bd9580 -> SUSPICIOUS ***Unknown*** 48 8b c4 48 89 58 08 48 89 50 10 55 56 57 41 54
  Callback fffffa8004bca6b0 -> SUSPICIOUS ***Unknown*** 33 c0 c3 cc 40 53 48 83 ec 20 48 8b 89 50 01 00
```

## Commands examples

Listing modules (with or without filter):
```
#>> lm winp
 fffff806bd4f0000    10000  \??\C:\Kdrill\winpmem_x64.sys
```

Display a dump at a specific address:
```
#>> dq nt 40
 FFFFF80668000000  0000000300905A4D 0000FFFF00000004  MZ..........##..
 FFFFF80668000010  00000000000000B8 0000000000000040  ........@.......
 FFFFF80668000020  0000000000000000 0000000000000000  ................
 FFFFF80668000030  0000000000000000 0000011800000000  ................
```

Kdrill embeds a LDE to have a minimal x86 disassembly. You can have a tiny view of the opcodes with it:
```
#>> u nt!NtReadFile 10
> fffff806685f44d0 | 4c894c2420                       |
  fffff806685f44d5 | 4c89442418                       |
  fffff806685f44da | 4889542410                       |
  fffff806685f44df | 53                               |
  fffff806685f44e0 | 56                               |
  fffff806685f44e1 | 57                               |
```

Display a dump at an pointed address:
```
#>> dq poi(nt!LpcPortObjectType)
 FFFFAA0F7DD524E0  FFFFAA0F7DD524E0 FFFFAA0F7DD524E0  .$.}..##.$.}..##
 FFFFAA0F7DD524F0  0000000000140012 FFFFD5000BF7DC90  ..............##
 FFFFAA0F7DD52500  00000000000000F9 0000107C0000002E  ............|...
 FFFFAA0F7DD52510  0000140B00000F31 000000000000137D  1.......}.......
```

You can display a chunk header of data with a reference in the pool:
```
#>> fpool poi(nt!LpcPortObjectType)
Pool        : ffffaa0f7dd52470
  Tag       : ObjT
  Size      : 150
  Prev Size : 0
```

Listing object directory objects:
```
#>> winobj \Callback
 Callback        \Callback\IGD_WNICShareObj  (ffffaa0f8697ae30)
 Callback        \Callback\WdProcessNotificationCallback  (ffffaa0f7ebf9d30)
 Callback        \Callback\LLTDCallbackRspndr0006008004000000  (ffffaa0f88872c60)
[...]
```

Getting informations about a random object in memory:
```
#>> !addr ffffaa0f7ed3fb10
Pool        : ffffaa0f7ed3fac0
  Tag       : Devi
  Size      : 210
  Prev Size : 0
#>> !addr FFFFF80668CFB280
fffff80668cfb280 in \SystemRoot\system32\ntoskrnl.exe
ntoskrnl+cfb280
```

Get PTE rights of a page:
```
#>> list fffff80668cfb280
    FFFFF80668CFB000 rw--
```

List the relation between kernel memory address and a mapped file:
```
#>> filecache
Vacb : ffffaa0f7dde4000 ; size : 6
0xffffc186e4100000 \Windows\System32\catroot2\edb.log (9684)
0xffffc186fb4c0000 \$MapAttributeValue (320)
[...]
```

Help infos.
```
#>> ?
  ci : check if some drivers codes are modified (for file dump use "offline 1" command to download them from MS)
  fpg : Find if PatchGuard and check if it's running
  cirp : check IRP table of all drivers
  cio : check IRP table of PnP devices
  cci : check g_CiOptions state and CI DSE callbacks
  ccb : check Callback directory
  cndis : check NDIS callbacks
  cnetio : check FwpkCLNT/NetIo callbacks
  cfltmgr : check FltMgr callbacks
  ctimer : check DPC timers
  cidt : check IDT entries
  pe : check kernel memory to find hidden drivers
  drv_stack : display stacks devices to go to the driver
  filecache : Find Vacbs and crawl PFN to identify files mapped
  winobj [\Device] : list objects
  list start end : display memory
  lm : list modules
  dump addr length: display memory
  d[bdq] addr [length]: display memory
  !d[bdq] addr [length]: display physical memory
  fpool ADDR : Find pool chunck of address
  pool ADDR : Get informations on a pool chunck
  obj ADDR : Get informations on an object
  v[v0] : verbose [very/stop]
  offline [0/1] : set 1 if you are analyzing cold dump
  cr3 addr : set CR3 register
  ncr3 : find next CR3 valid value
  o2p 0x123 : file offset to phys address
  p2v 0x123 : phys address to virtual address
  o2v 0x123 : file offset to virtual address
  ? : help
```

# Acknowledgments

- LDE is based on Beatrix work: https://github.com/BeaEngine/lde64
- Winpmem for his driver https://github.com/Velocidex/WinPmem/blob/master/src/binaries/winpmem_x64.sys
