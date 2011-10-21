AddressInfo(a0 192.168.0.15 00:90:fb:25:d8:77);
AddressInfo(a1 192.168.0.16 00:90:fb:25:d8:78);
AddressInfo(a2 192.168.0.17 00:90:fb:25:d8:79);

out0 :: ToOcteon(0,ATOMIC_TAG);
out1 :: ToOcteon(1,ATOMIC_TAG);
out2 :: Discard;

in0 :: FromOcteon(0,1,2);
in1 :: FromOcteon(0,1,2);

c0 :: Classifier(12/0800 23/01, 12/0806 20/0002, 12/0806 20/0001)
  -> Strip(14)
  -> CheckIPHeader
  -> ICMPPingResponder
  -> eth0 :: ARPQuerier(a0)
  -> out0;

c0[1]
  -> [1] eth0;

c0[2]
  -> ARPResponder(a0)
  -> out0;

c1 :: Classifier(12/0800 23/01, 12/0806 20/0002, 12/0806 20/0001)
  -> Strip(14)
  -> CheckIPHeader
  -> ICMPPingResponder
  -> eth1 :: ARPQuerier(a1)
  -> out1;

c1[1]
  -> [1] eth1;

c1[2]
  -> ARPResponder(a1)
  -> out1;

c2 :: Classifier(12/0800 23/01, 12/0806 20/0002, 12/0806 20/0001)
  -> Strip(14)
  -> CheckIPHeader
  -> ICMPPingResponder
  -> eth2 :: ARPQuerier(a2)
  -> out2;

c2[1]
  -> [1] eth2;

c2[2]
  -> ARPResponder(a2)
  -> out2;

eth0[1]
  -> TagOcteon(NULL)
  -> out0;

eth1[1]
  -> TagOcteon(NULL)
  -> out1;

eth2[1]
  -> TagOcteon(NULL)
  -> out2;

in0[0] -> c0;
in0[1] -> c1;
in0[2] -> c2;

in1[0] -> c0;
in1[1] -> c1;
in1[2] -> c2;

StaticThreadSched(in0 0,in1 1);
