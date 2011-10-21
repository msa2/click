AddressInfo(a0 192.168.0.15 00:90:fb:25:d8:77);

out0 :: ToOcteon(0,ATOMIC_TAG);

in0 :: FromOcteon
  -> c :: Classifier(12/0800 23/01, 12/0806 20/0002, 12/0806 20/0001)
  -> Strip(14)
  -> CheckIPHeader
  -> ICMPPingResponder
  -> eth0 :: ARPQuerier(a0)
  -> out0;

eth0[1]
  -> TagOcteon(NULL)
  -> out0;

c[1]
  -> [1] eth0;

c[2]
  -> ARPResponder(a0)
  -> out0;
