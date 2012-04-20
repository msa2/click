// -*- c-basic-offset: 4 -*-

/*
 * ipsecselector.{cc,hh} -- IPsecSelector
 * Markku Savela <Markku.Savela@vtt.fi>
 *
 * Copyright (c) 2012 VTT Technical Research Centre of Finland
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */
#include <stdlib.h>
#include <click/config.h>
#include <click/args.hh>
#include <click/error.hh>
#include <click/nameinfo.hh>
#include <click/ipaddress.hh>
#include <click/ip6address.hh>
#include "ipsecselector.hh"

CLICK_DECLS

IPsecSelector::IPsecSelector()
{
    _selector = IPsec::Selector();
}

IPsecSelector::~IPsecSelector()
{
    delete[] _selector.list;
}

static int parse_port(const String &s, uint8_t proto, uint16_t &port, const ArgContext &args)
{
    if (proto)
	return IPPortArg(proto).parse(s, port, args);
    return IntArg().parse(s, port);
}

// !!! TODO:
// !!! - check/verify working of MATCH_INBOUND/MATCH_OUTBOUND
// !!! - check/verify working of MATCH_RANGE
static int parse_matcher(const String &s, int mode, IPsec::Item &item, const ArgContext &args)
{
    const int hashmark = s.find_left('#');
    const int addrlen = hashmark < 0 ? s.length() : hashmark;
    if (addrlen > 0) {

	// parse address expression
	//	low
	//	low/prefix
	// => IP[6]PrefixArg(true).parse("low[/prefix]", addr, mask);
	//	low-high
	//	low&mask
	// => IP[6]AddressArg().parse("low", addr);
	//    IP[6]AddressArg().parse("high|mask", mask);
	//
	const String addr = s.substring(0, addrlen);
	const int range = addr.find_left('-');
	const int mask = addr.find_left('&');

	if (range >= 0 && mask >=0) {
	    // Malformed address, cannot have both '-' and '&' in
	    // same expression
	    return args.errh()->error("Cannot have both '.' and '&' in address expression (%s)",
				      addr.c_str());
	}

	if (range < 0 && mask < 0) {
	    // Either single address or address/prefix. If addr is actually a reference to
	    // AddressInfo, need try parsing first without bare address. If bare address is
	    // allowed, the net/prefix combination is not picked up from AddressInfo.
	    if (!IPsecPrefixArg().parse(addr, item.val.addr[mode], item.msk.addr[mode], args) &&
		!IPsecPrefixArg(true).parse(addr, item.val.addr[mode], item.msk.addr[mode], args))
		return args.errh()->error("'%s' does not parse as address/prefix", addr.c_str());
	} else {
	    // Address expression has either '-' (range) or
	    // '&' (mask) serator. Parse both parts separately
	    const int split = range >= 0 ? range : mask;
	    const String s1 = addr.substring(0, split);
	    const String s2 = addr.substring(split+1);

	    if (!IPsecAddressArg().parse(s1, item.val.addr[mode], args))
		return args.errh()->error("'%s' does not parse as address", s1.c_str());
	    if (!IPsecAddressArg().parse(s2, item.msk.addr[mode], args))
		return args.errh()->error("'%s' does not parse as address", s2.c_str());
	    if (range >= 0)
		item.val.proto |= (mode == IPsec::REMOTE) ?
		    IPsec::MATCH_RADDR_RANGE : IPsec::MATCH_LADDR_RANGE;
	}
	if (range < 0) {
	    // If masked format, clean out the extra bits from the value part.
	    item.val.addr[mode].in6_u.u6_addr64[0] &= item.msk.addr[mode].in6_u.u6_addr64[0];
	    item.val.addr[mode].in6_u.u6_addr64[1] &= item.msk.addr[mode].in6_u.u6_addr64[1];
	}
    }
    if (hashmark >= 0) {
	// parse protocol:port expression (hashmark != NULL)
	//	[proto:]low
	//	[proto:]low-high
	const String prot = s.substring(hashmark+1);
	uint8_t ip_proto = item.val.proto & 0xFF;
	int colon = prot.find_left(':');

	if (colon >= 0) {
	    int new_proto;
	    if (!NamedIntArg(NameInfo::T_IP_PROTO).parse(prot.substring(0, colon), new_proto, args))
		return -1;
	    if ((item.msk.proto & 0xFF) && new_proto != ip_proto) {
		// proto already defined (cannot define different
		// proto for LOCAL and REMOTE).
		return args.errh()->error("Cannot have different protocol for LOCAL and REMOTE");
	    }
	    ip_proto = new_proto;
	    item.val.proto |= 0xFF & ip_proto;
	    item.msk.proto = 0xFF;
	}
	const String ports = colon < 0 ? prot : prot.substring(colon+1);
	if (ports.length() == 0)
	    return 0; // No specific ports or type code

	// ... fix later, now just magic protocol numbers...
	if (ip_proto == 1 || ip_proto == 58 || ip_proto == 135) {
	    // For ICMP, ICMPv6 and MH the port information is type (and code)
	    // and it can be specified only in LOCAL matcher.
	    if (mode != IPsec::LOCAL)
		return args.errh()->error
		    ("ICMP or MH type selector is only allowed for LOCAL selector");
	    else if (item.val.proto & IPsec::MATCH_PORTS)
		return args.errh()->error("Cannot mix port and ICMP/MH type selectors");
	    item.val.proto |= IPsec::MATCH_TYPE;
	} else if (item.val.proto & IPsec::MATCH_TYPE)
	    return args.errh()->error("Cannot mix port and ICMP/MH type selectors");
	else
	    item.val.proto |= IPsec::MATCH_PORTS;

	int range = ports.find_left('-');
	if (range >= 0) {
	    // Port range
	    const String s1 = ports.substring(0, range);
	    const String s2 = ports.substring(range+1);
	    if (!parse_port(s1, ip_proto, item.val.port[mode], args))
		return args.errh()->error("'%s' does not parse as port", s1.c_str());
	    if (!parse_port(s2, ip_proto, item.msk.port[mode], args))
		return args.errh()->error("'%s' does not parse as port", s2.c_str());
	    item.val.proto |= (mode == IPsec::REMOTE) ?
		IPsec::MATCH_RPORT_RANGE : IPsec::MATCH_LPORT_RANGE;
	} else {
	    // Single value port
	    if (!parse_port(ports, ip_proto, item.val.port[mode], args))
		return args.errh()->error("'%s' does not parse as port", ports.c_str());
	    item.msk.port[mode] = 0xFFFF;
	}
    }
    return 0;
}

int IPsecSelector::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String remote;
    String local;
    String dir;

    if (Args(conf, this, errh)
	.read_p("REMOTE", AnyArg(), remote)
	.read_p("LOCAL", AnyArg(), local)
	.read_p("DIRECTION", KeywordArg(), dir)
	.complete() < 0)
	return -1;

    IPsec::Item initial = IPsec::Item();
    if (dir.length() > 0) {
	if (dir == "IN")
	    initial.val.proto |= IPsec::MATCH_INBOUND; // Limit selector to inbound only
	else if (dir == "OUT")
	    initial.val.proto |= IPsec::MATCH_OUTBOUND; // Limit selector to outbound only
	else
	    return errh->error("Unrecognized DIRECTION argument '%s'", dir.c_str());
	initial.msk.proto |= IPsec::MATCH_DIRECTION;
    }

    Vector<String> rm;
    Vector<String> lm;

    cp_spacevec(remote, rm);
    cp_spacevec(local, lm);

    IPsec::Item *list;
    _selector.length = rm.size() > lm.size() ? rm.size() : lm.size();
    _selector.list = list = _selector.length > 0 ? new IPsec::Item[_selector.length] : NULL;

    for (int i = 0; i < (int)_selector.length; ++i) {

	const ArgContext args(this, errh);

	list[i] = initial;

	if (i < rm.size() && parse_matcher(rm[i], IPsec::REMOTE, list[i], args))
	    return -1;
	if (i < lm.size() && parse_matcher(lm[i], IPsec::LOCAL, list[i], args))
	    return -1;
    }
    return 0;
}


CLICK_ENDDECLS
EXPORT_ELEMENT(IPsecSelector)
