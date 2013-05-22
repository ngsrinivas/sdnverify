/*Topology*/
const
 NUMSWITCHES: 3;
 MAXSWITCHID: NUMSWITCHES - 1;
 NUMPORTS: 3;
 NUMHOSTS: 3;
 NUMDEVICES: NUMHOSTS+NUMSWITCHES;
 MAXHOSTID: NUMHOSTS - 1;
 NUMLINKS: 6; -- max. np. of physical links 
 NUMENDPOINTSPERLINK: 2; 
 EXPMACLENGTH: NUMHOSTS+NUMSWITCHES*NUMPORTS; --each port has a unique mac address
 CONST_N: 100; -- Pick any value greater than EXPMACLENGTH
 HEADERMAXVAL:  CONST_N*CONST_N*CONST_N*CONST_N + CONST_N*CONST_N*CONST_N + CONST_N*CONST_N*(EXPMACLENGTH-1) + CONST_N * (EXPMACLENGTH-1) + (EXPMACLENGTH-1); 
 NUMMICROFLOWS: NUMHOSTS; --can make it NUMHOSTS - 1
 DEBUG: false;
 INTERFERENCE_BOUND: 1;

type 
 MacAddress: 0..(EXPMACLENGTH-1);
 PacketHeaderType: 0..HEADERMAXVAL;
 PacketType: enum{req,ack};
 PacketTag: enum{conc,env};
 DeviceType: enum{HOST, SWITCHDEVICE}; -- used to access hostId and switchID together in a polymophic kind of way

 ActionType: enum{FORWARD, null};
 CommandType: enum{INSTALL, FLOOD};
 PortID: 0..(NUMPORTS-1);
 SwitchID: 0..(NUMSWITCHES-1);
 LinkID: 0..(NUMLINKS-1);
 DeviceID: 0..(NUMHOSTS+NUMSWITCHES-1);
 SecureChannelID: SwitchID;

 Link: record
  end1Type: DeviceType;
--  end1ID: 0..(NUMDEVICES-1);
  end1ID: DeviceID;
  end2Type: DeviceType;
--  end2ID: 0..(NUMDEVICES-1);
  end2ID: DeviceID;
  status: 0..2; --0 means no packet, 1 means packet from lower id switch OR from Host to switch and 2 means from higher id OR from Switch to host
  pkt: PacketHeaderType;
 linkDirSpanning: enum{end1ToEnd2,end2ToEnd1,noRes,blockLink};
 end;

 SecureChannel: record --for link of switch to controller
 status: enum{reqToCtrl, ackReqToCtrl, noReq};
 pkt: PacketHeaderType;
 cmd: CommandType;
 inPort: PortID;
 outPort: PortID;
 -- Maybe add auxiliary information here for completing actions like installing new flows
 end;

var
 topo: array [LinkID] of Link; --stores which link connected to which switch/host
 secureChannels: array [SecureChannelID] of SecureChannel; -- connects switches to controller 
 debug: Boolean;
-- env_o: 0..INTERFERENCE_BOUND;
 env_o: Boolean;
 invNoLive: 0..1;

/*Host state*/
type 
 Host: record
  --hostMac: MacAddress;
  link: LinkID;
 end;
 
 HostID: 0..(NUMHOSTS-1);

var 
 hosts: array [HostID] of Host;

/*Switch state -- canonicalized flows -- essentially a mapping from header state space partition to (action,softtimeout,hardtimeout)*/
const
 MAXTIMEOUTVAL: 10;

type

 TimeoutType: 0..MAXTIMEOUTVAL;
 MicroFlowID: 0..(NUMMICROFLOWS-1);

 MicroFlow: record
  action: ActionType;  
  softTimeout: TimeoutType;
  hardTimeout: TimeoutType;
  dst: MacAddress;
 end;

 Flow: record -- mapping from pkt src, inport to outport, dst
  src: MacAddress;
  nextAvailableMicroFlowID:  MicroFlowID;
  microFlows: array [MicroFlowID] of MicroFlow;
 end;

 Port: record
  link: LinkID;
  --portMac: MacAddress;
 end;

 SwitchTypeOptim: record 
  flowTableOptim: array [PortID] of array [HostID] of Boolean; -- keeps a record of the set of desitnation hosts reachable from a port

  --flowTable: array [PortID] of array [PortID] of Flow; -- for now a 3D array which takes input port, output port and matches header 
  ports: array [PortID] of Port; -- ports of switches are connected to links 
  mark: Boolean; --to specify if a switch has been visited by packet on which property is specified
 end;

/* 
 SwitchType: record 
  flowTable: array [PortID] of array [PortID] of Flow; -- for now a 3D array which takes input port, output port and matches header 
  ports: array [PortID] of Port; -- ports of switches are connected to links 
  mark: Boolean; --to specify if a switch has been visited by packet on which property is specified
 end;
*/
var
 switches: array [SwitchID] of SwitchTypeOptim;

/*Controller State -- Depends on application*/

type

 MacTableRecord: record
  port: PortID;
  valid: Boolean;
 end;

 MacTable: array [MacAddress] of MacTableRecord;

var
 ctrl_state: array [SwitchID] of MacTable;


-----------------------------------------------------Procedures------------------------------------------------------------------
/*Packets*/

/*Returns mac address of source host of a packet*/
function getSrcHostMac(pkt: PacketHeaderType): MacAddress;
var hostID: HostID;
begin
if debug then
put "getSrcHostMac called for packet: "; put pkt; put " and returning src as "; put (pkt/(CONST_N)) % CONST_N; put " Also, Const_n is: "; put CONST_N; put "\n";
endif;
return (pkt/(CONST_N)) % CONST_N;
endFunction;

function getSrcHostID(pkt: PacketHeaderType): HostID;
var hostID: HostID;
begin
return (pkt/(CONST_N)) % CONST_N;
endFunction;

function getDstHostMac(pkt: PacketHeaderType): MacAddress;
begin
return (pkt) % CONST_N;
endFunction;

function getDstHostID(pkt: PacketHeaderType): HostID;
begin
return (pkt) % CONST_N;
endFunction;

function generatePacket(packetType: PacketType; dstHostMac: MacAddress; srcHostMac: MacAddress; packetTag: PacketTag): PacketHeaderType;
var header: PacketHeaderType;
var intPacketType, intPacketTag: 0..1;
begin
if(packetType = req) then intPacketType := 0; else intPacketType := 1; endif;
if(packetTag = conc) then intPacketTag := 0; else intPacketTag := 1; endif;

header := intPacketTag*CONST_N*CONST_N*CONST_N + intPacketType*CONST_N*CONST_N + srcHostMac*CONST_N + dstHostMac;

if debug then 
 put "Generating req Packet for srcHostMAC: "; put srcHostMac; put "; dstHostMAC: "; put dstHostMac; put "\n";
endif;

return header;
endFunction;

function isEnvironmentPacket(pkt: PacketHeaderType): Boolean;
var val: 0..CONST_N*CONST_N*CONST_N;
begin
val := CONST_N*CONST_N*CONST_N;
if (((pkt/val)%val)=0) then return false; else return true; endif;
endFunction;

function typeOfPacket(pkt: PacketHeaderType): PacketType;
var val: 0..CONST_N*CONST_N*CONST_N;
begin
val := CONST_N*CONST_N;
if (((pkt/val)%val)=0) then return req; else return ack; endif;
endFunction;

/*
function getSrcDeviceMac(pkt: PacketHeaderType): MacAddress;
Begin
return pkt % CONST_N;
EndFunction;
*/

/*Topology -- connects Links between switches/hosts and secure channels between switches and controller*/
function generateMac(deviceID: DeviceID; device: DeviceType; portID:PortID): MacAddress;
begin
if(device=HOST) then return 1*deviceID; endif;  --1* is done to HACK around murphi compiler issues
if(device=SWITCHDEVICE) then return (NUMHOSTS-1) + (deviceID)*NUMPORTS + portID; endif;
error "Invalid Device";
endFunction;

function getMac(deviceID: DeviceID; device: DeviceType; portID: PortID): MacAddress;
begin
if(device=HOST) then return 1*deviceID; endif; --1* is done to HACK around murphi compiler issues
if(device=SWITCHDEVICE) then return NUMHOSTS + (deviceID)*NUMPORTS + portID; endif;
error "Invalid Device";
endFunction;

function getDeviceMac(randSrcDeviceType: DeviceType; randSrcDeviceSwitchID: SwitchID; randPortID: PortID; randSrcDeviceHostID: HostID): MacAddress;
begin
if(randSrcDeviceType=HOST) then return getMac(randSrcDeviceHostID, randSrcDeviceType, randPortID); endif; --1* is done to HACK around murphi compiler issues
if(randSrcDeviceType=SWITCHDEVICE) then return getMac(randSrcDeviceSwitchID, randSrcDeviceType, randPortID); endif;
error "getDeviceMac: Invalid Device";
endFunction;

procedure assignMacs();
--hosts
for hostID: HostID do
    --hosts[hostID].hostMac := generateMac(hostID, HOST, 0);
endFor;

--switches
for switchID: SwitchID do
  for portID: PortID do
    --switches[switchID].ports[portID].portMac := generateMac(switchID, SWITCHDEVICE, portID);
  endFor;
endFor;
endProcedure;


-- inits a link from first device at end1 to next device at end2
procedure initLink(linkID: LinkID; end1DeviceID: DeviceID; end1SwitchPortID:PortID; end1DeviceType: DeviceType; end2DeviceID:DeviceID;  end2SwitchPortID:PortID; end2DeviceType:DeviceType);
begin

-- initializing link buffer
topo[linkID].status := 0;
topo[linkID].pkt := 0; 

-- for end1
if(end1DeviceType=HOST) then
 topo[linkID].end1Type := HOST; 
 topo[linkID].end1ID := end1DeviceID; 
 hosts[end1DeviceID].link := linkID;
else
 topo[linkID].end1Type := SWITCHDEVICE; 
 topo[linkID].end1ID := end1DeviceID; 
 --switches[end1DeviceID].link := linkID;
 switches[end1DeviceID].ports[end1SwitchPortID].link := linkID;
endif;

-- for end2
if(end2DeviceType=HOST) then
 topo[linkID].end2Type := HOST; 
 topo[linkID].end2ID := end2DeviceID; 
 hosts[end2DeviceID].link := linkID;
else
 topo[linkID].end2Type := SWITCHDEVICE; 
 topo[linkID].end2ID := end2DeviceID; 
 --switches[end2DeviceID].link := linkID;
 switches[end2DeviceID].ports[end2SwitchPortID].link := linkID;

endif;
endProcedure;

procedure initTopo(); --this function initializes the topology 
begin

--Initialize links by calling initLink(linkID, end1DeviceID, end1SwitchPortID, end1DeviceType, end2DeviceID, end2SwitchPortID, end2DeviceType)
--Path from HA to HB

--First Link id 0
initLink(0, 0, 0, HOST, 0, 0, SWITCHDEVICE);

--Second Link id 1
initLink(1, 0, 1, SWITCHDEVICE, 1, 0, SWITCHDEVICE);

--Third Link id 3
initLink(3, 1, 1, SWITCHDEVICE, 1, 0, HOST);

--Path from HA to HC
--First link id 0 Covered

--Second Link id 2
initLink(2, 0, 2, SWITCHDEVICE, 2, 0, SWITCHDEVICE);

--Third link id 5
initLink(5, 2, 2, SWITCHDEVICE, 2, 0, HOST);

--Path from HC to HB
--First Link id 5 Covered

--Second Link: id 4
initLink(4, 2, 1, SWITCHDEVICE, 1, 2, SWITCHDEVICE);

--Third Link id 3 Covered


--Spanning Tree - link 4 blocked
for linkID:LinkID do
 topo[linkID].linkDirSpanning := noRes;
endFor;

topo[4].linkDirSpanning := blockLink;


--Initilizing secure channels
for switchID: SwitchID do
 secureChannels[switchID].status := noReq; 
endFor;

-- assign mac addresses
assignMacs();

 -- Maybe add auxiliary information here for completing actions like installing new flows
endprocedure;

/*
procedure initTopo(); --this function initializes the topology 
begin

--For Links
--First Link
topo[0].end1Type := HOST;
topo[0].end1ID := 0; 
hosts[0].link := 0;

topo[0].end2Type := SWITCHDEVICE;
topo[0].end2ID := 0;
switches[0].ports[0].link := 0;

topo[0].status := 0;
topo[0].pkt := 0; -- initialized a random value

--Second Link
topo[1].end1Type := SWITCHDEVICE;
topo[1].end1ID := 0; 
switches[0].ports[1].link := 1;

topo[1].end2Type := SWITCHDEVICE;
topo[1].end2ID := 1;
switches[1].ports[0].link := 1;

topo[1].status := 0;
topo[1].pkt := 0; -- initialized a random value

--Third Link
topo[2].end1Type := SWITCHDEVICE;
topo[2].end1ID := 1; 
switches[1].ports[1].link := 2;

topo[2].end2Type := HOST;
topo[2].end2ID := 1;
hosts[1].link := 2;

topo[2].status := 0;
topo[2].pkt := 0; -- initialized a random value

-- Forth Link
topo[3].end1Type := SWITCHDEVICE;
topo[3].end1ID := 0; 
switches[0].ports[2].link := 3;

topo[3].end2Type := SWITCHDEVICE;
topo[3].end2ID := 1;
switches[1].ports[2].link := 3;

topo[3].status := 0;
topo[3].pkt := 0; -- initialized a random value


--Spanning Tree - link 4 blocked
for linkID:LinkID do
 topo[linkID].linkDirSpanning := noRes;
endFor;

topo[3].linkDirSpanning := blockLink;

--For secure channel
for switchID: SwitchID do
 secureChannels[switchID].status := noReq; 
endFor;

-- assign mac addresses
assignMacs();

 -- Maybe add auxiliary information here for completing actions like installing new flows
endprocedure;
*/

--Checks if the device is connected to link linkID
function isLinkEndPoint(linkID: LinkID; deviceID: DeviceID; device: DeviceType): Boolean;
Begin
if(topo[linkID].end1Type=device)&(topo[linkID].end1ID=deviceID) then return true; endif;
if(topo[linkID].end2Type=device)&(topo[linkID].end2ID=deviceID) then return true; endif;
return false;
EndFunction;

--Checks if link linkID has a packet for device deviceID of type device
function doesLinkHavePacket(linkID: LinkID; deviceID: DeviceID; device: DeviceType): Boolean;
begin
-- First case - both ends of link are switches
if(topo[linkID].end1Type=SWITCHDEVICE)&(topo[linkID].end2Type=SWITCHDEVICE) then

  switch (topo[linkID].status)
  case 0: return false; -- no packet on link
  case 1: if(deviceID=topo[linkID].end1ID) then 
	     if (deviceID>topo[linkID].end2ID) then return true; endif; --as status 1 means packet FROM lower id switch and so for the higher id
          endif;
	  if(deviceID=topo[linkID].end2ID) then 
	     if (deviceID>topo[linkID].end1ID) then return true; endif;
          endif;
  case 2: if(deviceID=topo[linkID].end1ID) then 
	     if (deviceID<topo[linkID].end2ID) then return true; endif; --as status 2 means packet FROM higher id switch and so for the lower id
          endif;
	  if(deviceID=topo[linkID].end2ID) then 
	     if (deviceID<topo[linkID].end1ID) then return true; endif;
          endif;
  endSwitch;

else -- case when one of the endpoints is a host
  switch(topo[linkID].status)
  case 0: return false; -- no packet on link
  case 1: if(device=SWITCHDEVICE) then 
	    return true; -- status 1 means packet FROM host
	  endif;
  case 2: if(device=HOST) then 
	    return true; -- status 2 means packet FROM switch
	  endif;
  endSwitch;
endif;

return false;
endFunction;

procedure removePacketFromLink(linkID: LinkID);
begin
topo[linkID].status := 0;
endProcedure;


function getOtherEndDeviceID(linkID: LinkID; deviceID: DeviceID; device: DeviceType): DeviceID;
begin
if (topo[linkID].end1Type = device) & (topo[linkID].end1ID = deviceID) then 
   return topo[linkID].end2ID;
endif;
if (topo[linkID].end2Type = device) & (topo[linkID].end2ID = deviceID) then 
   return topo[linkID].end1ID;
endif;
assert false;
endFunction;

function getOtherEndDeviceType(linkID: LinkID; deviceID: DeviceID; device: DeviceType): DeviceType;
begin
if (topo[linkID].end1Type = device) & (topo[linkID].end1ID = deviceID) then 
   return topo[linkID].end2Type;
endif;
if (topo[linkID].end2Type = device) & (topo[linkID].end2ID = deviceID) then 
   return topo[linkID].end1Type;
endif;
assert false;
endFunction;

--checks if there is any packet alive in the network
function noLivePacket(): Boolean;
begin
-- checking if no packet on any link
for linkID: LinkID do
  if topo[linkID].status != 0 then return false; endif;
endFor;

--checking if no packet sent to controller either
for switchID: SwitchID do
 if secureChannels[switchID].status != noReq then
	return false;
 endif;
endFor;

return true;
endFunction;

/*Hosts*/
procedure initHosts();
begin
--host macs and links already assigned
endProcedure;

procedure sendPacketToLink(pkt: PacketHeaderType; linkID: LinkID; srcDeviceID: DeviceID; device: DeviceType); --it sends the packet to the link from host
var bypass: Boolean;
begin

bypass := false;

-- check topology
if (topo[linkID].linkDirSpanning = blockLink) then
  bypass := true;
endif;

if(!bypass) then
if(device=HOST) then
 topo[linkID].pkt := pkt;
 topo[linkID].status := 1;

if(debug) then
put "Sending Packet: "; put pkt; put "\n";
endif;

elsif(device=SWITCHDEVICE) then

--get other end  --0 means no packet, 1 means packet from lower id switch OR from Host to switch and 2 means from higher id OR from Switch to host
  if(getOtherEndDeviceType(linkID, srcDeviceID, device)=SWITCHDEVICE) then
	if(getOtherEndDeviceID(linkID, srcDeviceID, device)>srcDeviceID) then
           topo[linkID].pkt := pkt;
           topo[linkID].status := 1;
        endif;
	if(getOtherEndDeviceID(linkID, srcDeviceID, device)<srcDeviceID) then
           topo[linkID].pkt := pkt;
           topo[linkID].status := 2;
        endif;								   
  endif;
-- if other end is host then 2
  if(getOtherEndDeviceType(linkID, srcDeviceID, device)=HOST) then
     topo[linkID].pkt := pkt;
     topo[linkID].status := 2;							   
  endif;
 
else
error "invalid device";
endif;

endif;

endProcedure;


procedure sendPacketToLinkOLD(pkt: PacketHeaderType; linkID: LinkID; srcDeviceID: DeviceID; device: DeviceType); --it sends the packet to the link from host
begin
if(device=HOST) then
 topo[linkID].pkt := pkt;
 topo[linkID].status := 1;

if(debug) then
put "Sending Packet: "; put pkt; put "\n";
endif;

elsif(device=SWITCHDEVICE) then

--get other end  --0 means no packet, 1 means packet from lower id switch OR from Host to switch and 2 means from higher id OR from Switch to host
  if(getOtherEndDeviceType(linkID, srcDeviceID, device)=SWITCHDEVICE) then
	if(getOtherEndDeviceID(linkID, srcDeviceID, device)>srcDeviceID) then
           topo[linkID].pkt := pkt;
           topo[linkID].status := 1;
        endif;
	if(getOtherEndDeviceID(linkID, srcDeviceID, device)<srcDeviceID) then
           topo[linkID].pkt := pkt;
           topo[linkID].status := 2;
        endif;								   
  endif;
-- if other end is host then 2
  if(getOtherEndDeviceType(linkID, srcDeviceID, device)=HOST) then
     topo[linkID].pkt := pkt;
     topo[linkID].status := 2;							   
  endif;
 
else
error "invalid device";
endif;

endProcedure;

/*
--Initializing Switches
procedure initSwitches();
begin
for switchID: SwitchID do

-- mac address already initialized in assignMac()

--Initializing Flows
    for inPort: PortID do
      for outPort: PortID do
	--switches[switchID].flowTable[inPort][outPort].src := getMac(switchID,SWITCHDEVICE,inPort);
        switches[switchID].flowTable[inPort][outPort].nextAvailableMicroFlowID := 0;
        for micro: 0..(NUMMICROFLOWS-1) do
	   switches[switchID].flowTable[inPort][outPort].microFlows[micro].action := null;
	   switches[switchID].flowTable[inPort][outPort].microFlows[micro].dst := 0;
	   switches[switchID].flowTable[inPort][outPort].microFlows[micro].softTimeout := 0;
	   switches[switchID].flowTable[inPort][outPort].microFlows[micro].hardTimeout := 0;
        endFor;
      endFor;
    endFor;

switches[switchID].mark := false;

endFor;
endProcedure;
*/

--Initializing Switches
procedure initSwitchesOptim();
begin
for switchID: SwitchID do

-- mac address already initialized in assignMac()

--Initializing Flows
    for portID: PortID do
      for hostID: HostID do
        switches[switchID].flowTableOptim[portID][hostID] := false;
      endFor;
    endFor;

switches[switchID].mark := false;

endFor;
endProcedure;


--returns portID of the port of switchID connected to linkID
function getPortID(linkID: LinkID; switchID: SwitchID): PortID;
begin
for portID: PortID do
    if switches[switchID].ports[portID].link = linkID then return portID; endif;
endFor;
error "getPortID: No port connects switch switchID to link linkID";
endFunction;

--returns linkID of the link connecting to portID of switchID
function getLinkID(portID: PortID; switchID: SwitchID): LinkID;
begin
return switches[switchID].ports[portID].link;
endFunction;

--sends request to controller for advice with packet info
procedure sendController(inPacket: PacketHeaderType; inPort: PortID; switchID: SwitchID);
begin
if debug then
 put "SendController Called \n";
endif;

secureChannels[switchID].status := reqToCtrl;
secureChannels[switchID].pkt := inPacket;
secureChannels[switchID].inPort := inPort;
endProcedure;

--updates the flowtable by installing appropriate microflow and then increments next available microflowID pointer
procedure installFlow(inPort: PortID; outPort:PortID; inPacket: PacketHeaderType; switchID: SwitchID);
begin
 if((getDstHostID(inPacket)=0)|(getDstHostID(inPacket)=1)) then
  switches[switchID].flowTableOptim[outPort][getDstHostID(inPacket)] := true;
 endif;
endProcedure;

function getOutPortFromFlow(inPacket:PacketHeaderType; inPort: PortID; switchID: SwitchID): PortID;
begin
for guessedOutPort: PortID do
      if(switches[switchID].flowTableOptim[guessedOutPort][getDstHostID(inPacket)]) then 
	  return guessedOutPort; 
       endif;
endFor;
error "No matching flow for this packet";
endFunction;

function isThereMatchingMicroFlow(inPacket:PacketHeaderType; inPort: PortID; switchID: SwitchID): Boolean;
var srcMac: MacAddress;
begin
for guessedOutPort: PortID do
      if(switches[switchID].flowTableOptim[guessedOutPort][getDstHostID(inPacket)]) then 
	  return true; 
       endif;
endFor;
return false;
endFunction;

/*Controller*/
procedure initController();
begin
for switchID: SwitchID do
   for macAddress: MacAddress do
     ctrl_state[switchID][macAddress].valid := false; 
     ctrl_state[switchID][macAddress].port := 0;  
  endFor;
endFor;
endProcedure;



procedure cmdSwitch(switchID: SwitchID; cmd: CommandType; outPort: PortID);
begin
if debug then
put "cmdSwitch was called \n";
endif;

secureChannels[switchID].status := ackReqToCtrl;
secureChannels[switchID].cmd := cmd;
secureChannels[switchID].outPort := outPort;

endProcedure;


procedure resetMarks();
begin
for switchID: SwitchID do
 switches[switchID].mark := false;
endFor;
endProcedure;

---------------------------------------------------------Non-interference Lemmas-------------------------------------------------
/*function packetSanityCheck(packet: packetHeaderType): Boolean;
var header: PacketHeaderType;
    intPacketType, intPacketTag: 0..1;
    val: 0..CONST_N*CONST_N*CONST_N*CONST_N;
begin

--check if intPacketTag in 0..1
val := CONST_N*CONST_N*CONST_N*CONST_N;
if (((pkt/val)%val)>1) then return false; endif;

--check if intPacketType in 0..1
val := CONST_N*CONST_N*CONST_N;
if (((pkt/val)%val)>1) then return false; endif;

--check if host mac in range
val := CONST_N*CONST_N;
if (((pkt/val)%val)>(EXPMACLENGTH-1)) then return false; endif;

--check if dst mac in range
val := CONST_N;
if (((pkt/val)%val)>(EXPMACLENGTH-1)) then return false; endif;


if(packetType = req) then intPacketType := 0; else intPacketType := 1; endif;
if(packetTag = conc) then intPacketTag := 0; else intPacketTag := 1; endif;

header := intPacketTag*CONST_N*CONST_N*CONST_N*CONST_N + intPacketType*CONST_N*CONST_N*CONST_N + srcHostMac*CONST_N*CONST_N + dstHostMac * CONST_N + srcDeviceMac;

if debug then 
 put "Generating req Packet for srcHostMAC: "; put srcHostMac; put "; dstHostMAC: "; put dstHostMac; put "; srcDeviceMac: "; put srcDeviceMac; put "\n";
endif;

return header;

endFunction;


-- This function should check that the packet at the current switch comes from a valid source
function checkPktIntegrity( randPacketType: PacketType; randSrcDeviceType: DeviceType; randSrcDeviceSwitchID: SwitchID; randSrcDeviceHostID: HostID; randDstHostID: HostID; randSrcHostID: HostID; randPacketTag: PacketTag; randPortID: PortID): Boolean;
begin
return true;
endFunction;
*/

function shouldExploreAfterSymmetryReduction(switchID: SwitchID; portID: PortID): Boolean;
begin
if switchID = 2 then return false; endif;

return true;

endFunction;


-- This function should check that the packet at the current switch comes from a valid source
function checkPktIntegrity(inPacket: PacketHeaderType; switchID: SwitchID; linkID: LinkID): Boolean;
var pktLastDeviceMac:MacAddress;
var portID: PortID;
begin

portID := getPortID(linkID, switchID);

--switch 0

if(switchID=0) then
 
 if (portID=0) then
  if!(
      (getSrcHostMac(inPacket) = getMac(0,HOST,0))
      )
    then return false; 
  endif;
 endif;

 if (portID=1) then
  if!(
      (getSrcHostMac(inPacket) = getMac(1,HOST,0))
      )
    then return false; 
  endif;
 endif;

 if (portID=2) then
  if!(
      (getSrcHostMac(inPacket) = getMac(2,HOST,0))
      )
    then return false; 
  endif;
 endif;

endif;

-- switch 1

if(switchID=1) then

 if (portID=0) then
  if!(
      ((getSrcHostMac(inPacket) = getMac(0,HOST,0))|(getSrcHostMac(inPacket) = getMac(2,HOST,0)))
      )
    then return false; 
  endif;
 endif;

 if (portID=1) then
  if!(
      ((getSrcHostMac(inPacket) = getMac(1,HOST,0)))
      )
    then return false; 
  endif;
 endif;

 if (portID=2) then
   return false;
 endif;

endif;

-- switch 2

if(switchID=2) then

 if (portID=0) then
  if!(
      ((getSrcHostMac(inPacket) = getMac(0,HOST,0))|(getSrcHostMac(inPacket) = getMac(1,HOST,0)))
      )
    then return false; 
  endif;
 endif;

 if (portID=1) then
   return false;
 endif;

 if (portID=2) then
  if!(
      ((getSrcHostMac(inPacket) = getMac(2,HOST,0)))
      )
    then return false; 
  endif;
 endif;

endif;

/*-------------_TBD----------------------------
pktLastDeviceMac := getSrcDeviceMac(inPacket);

if(!isLinkEndPoint(linkID, switchID, SWITCHDEVICE)) then return false; endif;

if(getOtherEndDeviceType(linkID, switchID, SWITCHDEVICE)=HOST) then
      if (pktLastDeviceMac != getMac(getOtherEndDeviceID(linkID, switchID, SWITCHDEVICE),HOST,0)) then return false; endif;

      if (pktLastDeviceMac!=getSrcHostMac(inPacket)) then return false; endif;
endif;

if(getOtherEndDeviceType(linkID, switchID, SWITCHDEVICE)=SWITCHDEVICE) then
      if (pktLastDeviceMac != getMac(getOtherEndDeviceID(linkID, switchID, SWITCHDEVICE),SWITCHDEVICE, getPortID(linkID, getOtherEndDeviceID(linkID, switchID, SWITCHDEVICE)))) then return false; endif;
endif;
*/
return true;
endFunction;



---------------------------------------------------------Transitions--------------------------------------------------------------

/*startstate*/
ruleset hiD : HostID do
 startstate "Init"
   debug := DEBUG;
   invNoLive := 0;
   env_o := false;
   initTopo();
   initHosts();
   initSwitchesOptim(); 
   initController();
 endstartstate;
endruleset;

/*Randomly picks a host and generates a packet - but does so only if no packet is alive in the system
Currently, packet header is src + appended by dst. Thus header = 0/1*n^2 + src * n + dst (src,dst: 0..NUMHOSTS - 1; n > NUMHOSTS - say 10),
where, in 0/1, 0 stands for req and 1 stands for ack
*/
/*Host 0 sends packet to Host 1*/
rule "HostGeneratePacket" 
  noLivePacket()
-- & isLinkEndPoint(linkID,srcHostID,HOST)
 ==>
  var linkID: LinkID;
  var generatedPacket: PacketHeaderType;
begin
  linkID := hosts[0].link;
  generatedPacket := generatePacket(req, getMac(1,HOST,0), getMac(0,HOST,0), conc); 
  sendPacketToLink(generatedPacket, linkID, 0, HOST);
  resetMarks();
  invNoLive := 1;
endrule;

/*Hosts
Reply to a req packet with an ack packet to the source
*/
ruleset hostID: HostID do 
rule "HostListenForPacket" 
  doesLinkHavePacket(hosts[hostID].link, hostID, HOST) 
--& isLinkEndPoint(linkID, hostID, HOST)
 ==>
  var linkID: LinkID;
  var pkt: PacketHeaderType;
  var generatedPacket: PacketHeaderType;
begin
  linkID := hosts[hostID].link;
  pkt := topo[linkID].pkt;
--  if (typeOfPacket(pkt)=req) then assert false; endif;
--send_pkt(ack, hostID, getSrc(pkt)); --here the host sends an acknowledgement atomically
  if(getDstHostMac(pkt) = getMac(hostID,HOST,0)) then --else drop packet
    generatedPacket := generatePacket(ack, getSrcHostMac(pkt), getDstHostMac(pkt), conc);    
    sendPacketToLink(generatedPacket, linkID, hostID, HOST);
    resetMarks();
    else
    removePacketFromLink(linkID);
    resetMarks();
    --assert false;
  endif;
endrule;
endruleset;

/*switch - listens to the link for becoming 1 or 2 (i.e. packet there) - 1 indicates packet sent by guy with lower id and 2 is vice versa - 
and then grabs the packet and makes the link 0 again

Next, it decodes the packet and then does apropriate action:
-- check flow table
-- communicate with controller if needed and update flow table
-- do appropriate action which is essentially forwarding or flooding.
*/
ruleset switchID: SwitchID; portID: PortID do 
rule "SwitchListenForPacket" 
  doesLinkHavePacket(getLinkID(portID, switchID), switchID, SWITCHDEVICE) & isLinkEndPoint(getLinkID(portID, switchID), switchID, SWITCHDEVICE) 
 ==>
  var inPacket,generatedPacket: PacketHeaderType;
--  var srcMac: MacAddress;
  var inPort, outPort: PortID;
  var outLinkID: LinkID;
  var isMatching: Boolean;
  var linkID: LinkID;
begin

  linkID := getLinkID(portID, switchID);
  switches[switchID].mark := true;

  inPacket := topo[linkID].pkt;

  inPort := getPortID(linkID, switchID);
  isMatching := isThereMatchingMicroFlow(inPacket, inPort, switchID);
  if(isMatching) then -- i.e. if flowtable has entry for the packet
     outPort := getOutPortFromFlow(inPacket, inPort, switchID);
     outLinkID := getLinkID(outPort, switchID);
     generatedPacket := generatePacket(typeOfPacket(inPacket), getDstHostMac(inPacket), getSrcHostMac(inPacket), conc);
     sendPacketToLink(generatedPacket, outLinkID, switchID, SWITCHDEVICE);  -- Switch forwards the packet
     removePacketFromLink(linkID);
  else  
    if (secureChannels[switchID].status= noReq) then 
     sendController(inPacket, inPort, switchID); -- through secure channel    
     removePacketFromLink(linkID);
     else --i.e. keep waiting for controller to become empty
     switches[switchID].mark := false;
    endif;
  endif;
endrule;
endruleset;


/*switch - listens to the link for becoming 1 or 2 (i.e. packet there) - 1 indicates packet sent by guy with lower id and 2 is vice versa - 
and then grabs the packet and makes the link 0 again

Next, it decodes the packet and then does apropriate action:
-- check flow table
-- communicate with controller if needed and update flow table
-- do appropriate action which is essentially forwarding or flooding.
*/
--switches listen for controller commands
ruleset switchID: SwitchID; nonDetFloodPortID: PortID do 
rule "SwitchListenForController" 
  secureChannels[switchID].status = ackReqToCtrl & (secureChannels[switchID].inPort!=nonDetFloodPortID)
 ==>
  var 
    pkt, generatedPacket: PacketHeaderType;
    cmd: CommandType;
    outPort: PortID;
    inLinkID, outLinkID: LinkID;
begin
  outPort := secureChannels[switchID].outPort;
  cmd := secureChannels[switchID].cmd;
  pkt := secureChannels[switchID].pkt;

  if debug then 
    put "Just read Packet: "; put pkt; put " from securechannel. \n";
  endif;

  switch(cmd)
  case INSTALL: if debug then
                  put "SwitchListenForController Rule - case INSTALL\n";
                endif;
                --installFlow(secureChannels[switchID].inPort, secureChannels[switchID].outPort, secureChannels[switchID].pkt, switchID); --No timeout for now
		generatedPacket :=  generatePacket(typeOfPacket(pkt), getDstHostMac(pkt), getSrcHostMac(pkt), conc);
		inLinkID := getLinkID(secureChannels[switchID].inPort, switchID);
                outLinkID := getLinkID(secureChannels[switchID].outPort, switchID);

                if(!isEnvironmentPacket(pkt)) then
                  sendPacketToLink(generatedPacket, outLinkID, switchID, SWITCHDEVICE);  -- Switch forwards the packet
                  --removePacketFromLink(inLinkID);
                endif;

    case FLOOD: if debug then
                  put "SwitchListenForController Rule - case FLOOD\n";
                endif;
		generatedPacket :=  generatePacket(typeOfPacket(pkt), getDstHostMac(pkt), getSrcHostMac(pkt), conc);
		inLinkID := getLinkID(secureChannels[switchID].inPort, switchID);
                outLinkID := getLinkID(nonDetFloodPortID, switchID);
                if debug then
		 put "Sending packet: "; put generatedPacket; put " to outLinkID: "; put outLinkID;
                endif;

                if(!isEnvironmentPacket(pkt)) then
                  sendPacketToLink(generatedPacket, outLinkID, switchID, SWITCHDEVICE);  -- Switch forwards the packet but without installing flow in this case	  
		endif;
                --removePacketFromLink(inLinkID);
/*                for portID: PortID do
		  if portID != secureChannels[switchID].inPort then 
		    generatedPacket := generatePacket(req, portID, getDstHostMac(pkt), getSrcHostMac(pkt));
                    sendPacketToLink(generatedPacket, getLinkID(portID, switchID), switchID, SWITCHDEVICE);  -- Switch forwards the packet
                  endif;
                endFor;
                --removePacketFromLink(getLinkID(secureChannels[switchID].inPort, switchID));*/
  endSwitch;
  secureChannels[switchID].status := noReq;
endrule;
endruleset;

/*controller - listens to (switch-indexed) events from switches and then performs processing update according to appropriate event handler
-- controller gets data from switch by directly reading it's state - no communication necessary in this model
-- currently not implemented the moving around of switches/hosts dynamically in the network
*/
ruleset switchID: SwitchID do 
rule "ControllerListenForSwitch" 
  secureChannels[switchID].status = reqToCtrl
 ==>
  var pkt: PacketHeaderType;
  var outPort, inPort: PortID;
begin
  pkt := secureChannels[switchID].pkt;
  inPort := secureChannels[switchID].inPort;

--if !(isBcast(rdSrc(pkt))) then HACK - skipping isBcast - check with others
  ctrl_state[switchID][getSrcHostMac(pkt)].valid := true;
  ctrl_state[switchID][getSrcHostMac(pkt)].port := inPort;
--endif;

--  if !(isBcast(rdDst(pkt))) & (ctrl_state[switchID][rdDstMac(pkt)].valid) then - skipping isBcast - check with others
  if (ctrl_state[switchID][getDstHostMac(pkt)].valid) then 
     outPort := ctrl_state[switchID][getDstHostMac(pkt)].port;
     if debug then
      put "outPort: "; put outPort; put " ; inPort: "; put inPort; put "\n";
      put "getSrcHostMac(pkt) returns: "; put getSrcHostMac(pkt); put "\n";
      put "getDstHostMac(pkt) returns: "; put getDstHostMac(pkt); put "\n";
     endif;
     if(outPort!=inPort) then
      cmdSwitch(switchID, INSTALL, outPort);--install rule , send packet
     else
      cmdSwitch(switchID, FLOOD, 0); --flood here too
      --assert false;
     endif;
  else
    cmdSwitch(switchID, FLOOD, 0); --flood
  endif;
endrule;
endruleset;

/*to avoide secure channel state -- controller just dreams up of environment packet and executes*/
ruleset switchID: SwitchID; inPort: PortID; pktSrcHost: HostID; pktDstHost: HostID do 
rule "ControllerListenForEnvironSwitch" 
  --secureChannels[switchID].status = reqToCtrl
  env_o & checkPktIntegrity(generatePacket(req, getMac(pktSrcHost,HOST,0), getMac(pktDstHost,HOST,0), env),switchID, getLinkID(inPort,switchID)) 
  & (pktSrcHost != pktDstHost)
 ==>
  var pkt: PacketHeaderType;
  var outPort: PortID;
begin
  pkt := generatePacket(req, getMac(pktSrcHost,HOST,0), getMac(pktDstHost,HOST,0), env);

--if !(isBcast(rdSrc(pkt))) then HACK - skipping isBcast - check with others
  ctrl_state[switchID][getSrcHostMac(pkt)].valid := true;
  ctrl_state[switchID][getSrcHostMac(pkt)].port := inPort;
--endif;

--  if !(isBcast(rdDst(pkt))) & (ctrl_state[switchID][rdDstMac(pkt)].valid) then - skipping isBcast - check with others
  if (ctrl_state[switchID][getDstHostMac(pkt)].valid) then 
     outPort := ctrl_state[switchID][getDstHostMac(pkt)].port;
     if debug then
      put "outPort: "; put outPort; put " ; inPort: "; put inPort; put "\n";
      put "getSrcHostMac(pkt) returns: "; put getSrcHostMac(pkt); put "\n";
      put "getDstHostMac(pkt) returns: "; put getDstHostMac(pkt); put "\n";
     endif;
     if(outPort!=inPort) then
       installFlow(inPort, outPort, pkt, switchID); --No timeout for now
       --cmdSwitchEnv(switchID, INSTALL, inport, outPort, pkt);--install rule , send packet
     else
       --cmdSwitchEnv(switchID, FLOOD, 0); --flood here too
      --assert false;
     endif;
  else
    --cmdSwitchEnv(switchID, FLOOD, 0); --flood
  endif;
endrule;
endruleset;


invariant "noLoop" --if packet in system then in next state either packet is in system or it reaches the destination host
forall switchID: SwitchID; linkID: LinkID do 
  doesLinkHavePacket(linkID, switchID, SWITCHDEVICE) & isLinkEndPoint(linkID, switchID, SWITCHDEVICE) 
    -> (switches[switchID].mark = false)
end;

/*
invariant "livePacketAtALLTIMES" --if packet in system then in next state either packet is in system or it reaches the destination host
(invNoLive = 1) -> !noLivePacket();
*/

/*
invariant "non-interference lemmas"
forall switchID: SwitchID; linkID: LinkID do 
  doesLinkHavePacket(linkID, switchID, SWITCHDEVICE) & isLinkEndPoint(linkID, switchID, SWITCHDEVICE) 
    ->  checkPktIntegrity(typeOfPacket(topo[linkID].pkt), getOtherEndDeviceType(linkID, switchID, SWITCHDEVICE), getOtherEndDeviceID(linkID, switchID, SWITCHDEVICE), getOtherEndDeviceID(linkID, switchID, SWITCHDEVICE), getDstHostID(topo[linkID].pkt), getSrcHostID(topo[linkID].pkt), conc, getPortID(linkID, switchID))
end;
*/

invariant "non-interference lemmas"
forall switchID: SwitchID; linkID: LinkID do 
  doesLinkHavePacket(linkID, switchID, SWITCHDEVICE) & isLinkEndPoint(linkID, switchID, SWITCHDEVICE) 
    ->  checkPktIntegrity(topo[linkID].pkt, switchID, linkID)
end;
