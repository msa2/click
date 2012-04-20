//
// IPsec test configuration
//
// for this to work, you need (linux specific)
//
// 1) enable ip forwarding
//    echo 1 > /proc/sys/net/ipv4/ip_forward
//
// 2) turn off rp_filter on all involved interfaces
//    ... brutish, pick your needed lines...
//    echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
//    echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter
//    echo 0 > /proc/sys/net/ipv4/conf/eth1/rp_filter
//    echo 0 > /proc/sys/net/ipv4/conf/tun0/rp_filter
//
// Equivalent permanent confs can be enabled in (Ubuntu)
//    /etc/sysctl.d/10-network-security.conf

// When using this configuration, the AddressInfo below
// needs to be edited for the other end.
AddressInfo(
	// The "inner net" protected by the IPsec, and address of this host there
	INNERNET 10.0.0.1/8,

	// Address of the remote security gateway
	SGW 192.168.0.15,
	// Fake source address for outer tunnel (it should be the
	// real source, but Linux refuses to route packets from
	// tun device if the source is being used by another
	// device (eth1) -- this is only for testing purposes and
	// can picked freely as long as it is not used on any real
	// interface and passes through your outbound gateways.
	FAKEME 192.168.1.14,
	// My real source address on eth1. Only required because
	// the inbound now has to deal with ARP.
	REALME 192.168.0.14 00:13:3b:02:b3:96)

host :: KernelTun(INNERNET)

// Ugly "inbound" packet puller. Nasty, because for complete
// IPsec, you would have to pull ALL packets from ALL
// interfaces and check them.
//
// For now, assumes IPsec packets come from eth1, I would
// prefer to leave ARP/ND to the kernel, and only pull the
// IPv4/IPv6 packets -- but FromDevice in my click refuses
// to put BPF_FILTER on. Note that all ip packets will reenter
// the host from the tun device (host). The 'out' is only used
// for ARP (and outbound PASS via 'eth', if we had those packets).

in  :: FromDevice(eth1,SNIFFER false);
out :: Queue(200) -> ToDevice(eth1);
in
  -> c :: Classifier(12/0800, 12/0806 20/0002, 12/0806 20/0001)
  -> Strip(14)
  -> CheckIPHeader
  -> inbound :: IPsecInbound(ipsec);
eth :: ARPQuerier(REALME) -> out;
eth[1]
  -> out;
c[1]
  -> [1] eth;
c[2]
  -> ARPResponder(REALME)
  -> out;


////////////////////////////////////////////////////////////////
// Rest of the configuration should be identical on both ends //
////////////////////////////////////////////////////////////////

t1 :: IPsecAdapter(ESP,AUTH 2,ENCR 12);
s1 :: IPsecSelector(REMOTE INNERNET);
a1 :: IPsecPolicyAction(TUNNEL SGW, PROPOSAL t1);

// Match everything and PASS without IPsec
// termination for the policy
s0 :: IPsecSelector();
a0 :: IPsecPolicyAction();

// IPsec([SELECTOR, ACTION]*...) - the RFC-4301 SPD and SAD component
//
// 2 input ports:
//
// [0]IPsec - outbound IPv4/IPv6 packets. Check the packet
// and route the packet to output port based on the policy
// If the port is for IPsec transform, annotate packet with
// the security association (SA).
//
// [1]IPsec - policy check for inbound IPv4/IPv6 packets.
// Check the packet and applied IPsec against the policy.
// If the packet has IPsec, the tranformation/decapsulation
// must have been done and the packet annotated with the
// security association (SA) -- see IPsecInbound element.

// 4..N output ports:
//
// IPsec[0] - BYPASS outbound packets from input port 0
// (packets that don't require IPsec).
//
// IPsec[1] - inbound packets from input port 1 which PASS
// the policy checks.
//
// IPsec[2] - inbound or outbound packets that fail policy
// check (DISCARD)
//
// IPsec[3] - outbound packets which triggered ACQUIRE
// processing that was not completed -- complete security
// association not available. The packet is annotated with
// the LARVAL outbound SA, that triggered ACQUIRE.
//
// IPsec[4..N-1] - the supported outbound IPsec transform
// pipelines. The first element in chain must be derived
// from IPsecTransform, which provides the transform/proposal
// information for the IPsec element (IPsecAdapter is one, and
// provides adaptation of security association to the "old"
// SADataTuple, which is used by existing old elements).

host ->
     // using "fixed" policy with only two selector to
     // actions (s1 -> a1) and the passall (s0 -> a0).
     [0] ipsec::IPsec(s1 a1, s0 a0);

ipsec[0] -> eth;	// outbound BYPASS
ipsec[1] -> host;	// inbound PASS
ipsec[2] -> Discard;	// inbound/outbound DISCARD
ipsec[3] -> Discard;	// ACQUIRE
// For now, only one example pipeline using old
// element for "HMAC-SHA + AES" (only for IPv4)
ipsec[4]
    -> t1
    -> IPsecESPEncap()
    -> IPsecAuthHMACSHA1(0)
    -> IPsecAES(1)
    -> IPsecEncap(esp)
    -> FixIPSrc(FAKEME)
    -> host;

// IPsecInbound - the IPsec frontend for inbound IPv4/IPv6 packets.
//
// 1 input port:
//
// [0]IPsecInbound - check if the packet requires IPsec processing
// (has ESP or AH) and route to appropriate output port.
//
// 1..N ouput ports:
//
// [0]IPsecInbound - plain inbound IP packets, not having IPsec
// headers -- annotation for security association is NULL.
//
// [1..N-1] - the supported inbound IPsec transform pipelines.
// The first element in chain must be derived from IPsecTransform,
// which provides the transform/proposal information for the IPsec
// element (IPsecAdapter is one, and provides adaptation of security
// association to the "old" SADataTuple, which is used by existing
// old elements).
// The packet is passed to output as is (no decapsulation in IPsecInbound),
// but the annotation for the inbound security association determined
// by the AH or ESP is set.


inbound[0]
	-> host;

// For now, only one example pipeline using old
// element for "HMAC-SHA + AES" (only for IPv4)
inbound[1]
	-> [1]t1[1]
	-> StripIPHeader()
	-> IPsecAES(0)
	-> IPsecAuthHMACSHA1(1)
	-> IPsecESPUnencap()
	-> CheckIPHeader()
	-> [1] ipsec;

// IPsecKM(IPSEC, [SELECTOR, SA]*...)
//
// Simple fixed manual key provider for processing the
// ACQUIRE generated by the IPsec. The ACQUIRE matching
// the sgw (selector vpn) is served by the provided fixed
// key data (sa) resulting one inbound and one outbound
// SA.
//
// IPsecKM would be the base class for elements that
// implement real key management like IKE, either
// directly within Click or provide a adapter to
// external key manager.

vpn :: IPsecSelector(REMOTE SGW);
sa :: IPsecSAData(
   SPI 1000,
   PROTO 3,
   ENCR 12 \<0123456789abcdef0123456789abcdef>,
   AUTH 2  \<0123456789abcdef0123456789abcdef>);

// Use TRIGGER for synthetic ACQUIRE without
// waiting any traffic. Use 's1' in this example,
// although in real life you might need to specify a
// separate specific selector for this. The selector
// for the policy may not do what you expect -- for
// example, if ranges are used, the trigger is done
// with the specified "low" value. Also, if KM like
// IKEv2 expects complete packet data with all
// fields specified, negotiation may fail.

km::IPsecKM(ipsec, TRIGGER s1, vpn, sa);
