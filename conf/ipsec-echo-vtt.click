//
// IPsec truly warped configution
//
// host tun 10.0.0.1/8
//  -> host ipsec ->
//    -> IPsec tunnel -> echo ipsec
//                             | echo reply
//    <- IPsec tunnel <- echo ipsec
//  <- host ipsec
// host tun
//
// The main value for this is to test IPsec and transforms
// withing single machine. Reading this may put your brain
// into a knot...
//
// To use (userlevel)
// sudo ./click ../conf/ipsec-vtt-echo.click
//
// ping 10.x.x.x.x (=! 10.0.0.1)

AddressInfo(
	INNERNET 10.0.0.1/8,
	ECHO 192.168.0.15,
	HOST 192.168.0.14)

host :: KernelTun(INNERNET)

t1 :: IPsecAdapter(ESP,AUTH 2,ENCR 12);
s1 :: IPsecSelector(REMOTE INNERNET);
h1 :: IPsecPolicyAction(TUNNEL ECHO, PROPOSAL t1);
e1 :: IPsecPolicyAction(TUNNEL HOST, PROPOSAL t1);
s0 :: IPsecSelector();
a0 :: IPsecPolicyAction();

host
   -> hostipsec :: IPsec(s1 h1, s0 a0);

hostinbound :: IPsecInbound(hostipsec);
echoipsec   :: IPsec(s1 e1, s0 a0);

echo :: CheckIPHeader
 -> ICMPPingResponder
 -> echoipsec;

echoinbound :: IPsecInbound(echoipsec)
  -> [1] echoipsec;
echoinbound[1]
  -> [2]t1[2]
  -> StripIPHeader()
  -> IPsecAES(0)
  -> IPsecAuthHMACSHA1(1)
  -> IPsecESPUnencap()
  -> CheckIPHeader()
  -> [1] echoipsec;

echoipsec[0] -> hostinbound;	// outbound BYPASS
echoipsec[1] -> echo;		// inbound PASS
echoipsec[2] -> Discard;	// inbound/outbound DISCARD
echoipsec[3] -> Discard;	// ACQUIRE
echoipsec[4]
  -> [3]t1[3]
  -> IPsecESPEncap()
  -> IPsecAuthHMACSHA1(0)
  -> IPsecAES(1)
  -> IPsecEncap(esp)
  -> FixIPSrc(ECHO)
  -> hostinbound;

hostipsec[0] -> echoinbound; 	// outbound BYPASS
hostipsec[1] -> host;	       	// inbound PASS
hostipsec[2] -> Discard;	// inbound/outbound DISCARD
hostipsec[3] -> Discard;	// ACQUIRE
hostipsec[4]
  -> t1
  -> IPsecESPEncap()
  -> IPsecAuthHMACSHA1(0)
  -> IPsecAES(1)
  -> IPsecEncap(esp)
  -> FixIPSrc(HOST)
  -> echoinbound;

hostinbound
  -> [1] hostipsec;
hostinbound[1]
  -> [1]t1[1]
  -> StripIPHeader()
  -> IPsecAES(0)
  -> IPsecAuthHMACSHA1(1)
  -> IPsecESPUnencap()
  -> CheckIPHeader()
  -> [1] hostipsec;

echovpn :: IPsecSelector(REMOTE ECHO);
hostvpn :: IPsecSelector(REMOTE HOST);

sa :: IPsecSAData(
   SPI 1000,
   PROTO 3,
   ENCR 12 \<0123456789abcdef0123456789abcdef>,
   AUTH 2  \<0123456789abcdef0123456789abcdef>);

hostkm::IPsecKM(hostipsec, TRIGGER s1, echovpn, sa);
echokm::IPsecKM(echoipsec, TRIGGER s1, hostvpn, sa);
