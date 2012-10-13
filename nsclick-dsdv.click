
// This file automatically generated at Wed Aug 15 18:35:52 BST 2012 with the following command:
// make-dsdv-config.pl --userlevel -i eth0 -a 10.0.0.1 --metric etx

// this configuration performs routing lookup *after* the interface
// queue, and only works with one interface.

AddressInfo(me 10.0.0.1 08:00:27:fd:a6:25);

elementclass TTLChecker {
  // expects grid packets with MAC headers --- place on output path to
  // decrement the IP TTL for next hop and provide traceroute support.  
  // 
  // push -> push 
  // 
  // output [0] passes through the Grid MAC packets 
  // 
  // output [1] produces ICMP error packets to be passed back to IP
  // routing layer 
 
  input -> cl :: Classifier(19/03, -);
  cl [1] -> output; // don't try to dec ttl for non-IP packets...

  cl [0] 
    -> MarkIPHeader(82) 
    -> cl2 :: IPClassifier(src host != me, -);

  cl2 [0]-> dec :: DecIPTTL; // only decrement ttl for packets we don't originate
  cl2 [1] -> output; 

  dec [0] -> output;
  dec [1] -> ICMPError(me, 11, 0) -> [1] output;
};

li :: GridLocationInfo2(0, 0, LOC_GOOD false);

elementclass FixupGridHeaders {
  $li | // LocationInfo element
  input  
    -> FixSrcLoc($li)
    -> SetGridChecksum
    -> output;
};

elementclass ToGridDev {
  // push, no output
  $dev |
  input -> cl :: Classifier(12/7ffe, // LinkStat 1
                            12/7ffd, // LinkStat 2
			    19/02,
			    19/03);
  prio :: PrioSched;
  cl [0] -> probe_counter :: Counter -> probe_q :: Queue(5) -> [0] prio;
  cl [1] -> probe_counter;
  cl [2] -> route_counter :: Counter -> route_q :: Queue(5) -> FixupGridHeaders(li) -> [1] prio;
  cl [3] ->  data_counter :: Counter ->  data_q :: Queue(5)  
    -> data_counter_out :: Counter
    -> tr :: TimeRange
    -> lr :: LookupLocalGridRoute2(me:eth, me:ip, nb) 
    -> FixupGridHeaders(li)
    -> data_counter_out2 :: Counter
    -> tr2 :: TimeRange
    -> [2] prio;
  prio
    -> dev_counter :: Counter
    -> t :: PullTee 
    -> ToDevice($dev);
  t [1] -> SetTimestamp -> Discard;
};

elementclass FromGridDev {
  // push, no input
  // `Grid' packets on first output
  // `LinkStat' packets on second output
  $dev, $mac |
  FromDevice($dev, PROMISC false) 
    -> t :: Tee 
    -> HostEtherFilter($mac, DROP_OWN true)
    -> cl :: Classifier(12/7fff, 12/7ffe, 12/7ffd, -);
  cl [0]  // `Grid' packets
    -> ck :: CheckGridHeader
    -> [0] output;
  cl [1]  // `LinkStat 1' packets
    -> [1] output;
  cl [2]  // `LinkStat 2' packets
    -> [1] output;
  cl [3] // everything else
    -> [2] output;
  t [1] -> Discard;
  ck [1] -> Print('Bad Grid header received', TIMESTAMP true, NBYTES 166) -> Discard;
};

elementclass GridLoad {
  // push, no input 

  // DATASIZE should be the size of the desired UDP packet (including
  // ethernet, Grid, and IP headers), plus 2 for alignment.  It must
  // be at least 120.  Most of this is stripped off to be re-used
  // later, avoiding expensive pushes in the UDP/IP and Grid
  // encapsulation.
  src :: InfiniteSource(ACTIVE false, DATASIZE 120)
    -> Strip(112) // 14 + 60 + 8 + 20 + 8 + 2 = 112 
                  // (eth + grid + grid_encap + ip + udp + 2 for alignment)
    -> seq :: IncrementSeqNo(FIRST 0, OFFSET 0)
    -> SetIPAddress(me)
    -> StoreIPAddress(4)
    -> udp :: UDPIPEncap(me, 1111, 0.0.0.0, 8021)
    -> count :: Counter
    -> tr :: TimeRange
    -> output;
}

ls2 :: Idle;
ls :: LinkStat(ETH me:eth, SIZE 148 );
metric :: ETXMetric(ls );

nb :: DSDVRouteTable(60000, 15000, 7500, 1000,
		     me:eth, me:ip, 
		     MAX_HOPS 100,
                     METRIC metric,
		     VERBOSE false
                        
                     );

grid_demux :: Classifier(19/03,    // encapsulated (data) packets
			 19/02);   // route advertisement packets

arp_demux :: Classifier(12/0806 20/0001, // arp queries
			12/0800);        // IP packets

// handles IP packets with no extra encapsulation
ip_demux :: IPClassifier(dst host me,    // ip for us
			 dst net me/24); // ip for Grid network

// handles IP packets with Grid data encapsulation
grid_data_demux :: IPClassifier(dst host me,    // ip for us
				dst net me/24); // ip for Grid network

// dev0
dev0 :: ToGridDev(eth0);
from_dev0 :: FromGridDev(eth0, me:eth) 
from_dev0 [0] -> Paint(0) -> grid_demux
from_dev0 [1] -> Paint(0) -> probe_cl :: Classifier(12/7ffe, 12/7ffd);

probe_cl [0] -> ls ->  probe_switch :: Switch(0) -> dev0;
probe_cl [1] -> ls2 -> probe_switch;

// support for traceroute
dec_ip_ttl :: TTLChecker -> dev0;
dec_ip_ttl [1] -> ip_demux;

grid_demux [0] -> CheckIPHeader( , 82) -> grid_data_demux;
grid_demux [1] -> nb -> dev0;

ip_input :: CheckIPHeader -> GetIPAddress(16) -> ip_demux;
;
to_host_encap :: KernelTun(me/24, HEADROOM 68, MTU 1432) -> ip_input;

// not needed in userlevel
Idle -> arp_demux [0] -> Idle;
arp_demux [1] -> Idle;

from_dev0 [2] -> Discard;

ControlSocket(tcp, 7777);

ip_demux [0] -> to_host_encap;  // loopback packet sent by us, required on BSD userlevel
ip_demux [1] -> GridEncap(me:eth, me:ip) -> dec_ip_ttl;   // forward packet sent by us

grid_data_demux [0] -> Strip(82) -> to_host_encap;  // receive packet from net for us  
grid_data_demux [1] -> dec_ip_ttl;                                // forward packet from net for someone else


// UDP packet generator
load :: GridLoad -> ip_input;
