// -*- c-basic-offset: 4 -*-

/*
 * ipsecpolicyaction.{cc,hh} -- IPsecPolicyAction
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
#include <click/ipaddress.hh>
#include <click/ip6address.hh>
#include "ipsectransform.hh"
#include "ipsecpolicyaction.hh"

CLICK_DECLS

IPsecPolicyAction::IPsecPolicyAction() : _action(IPsec::PolicyAction())
{
}

int IPsecPolicyAction::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String flags;
    String tunnel;

    delete[] _action.proposal.transform;
    _action = IPsec::PolicyAction();
    _action.hard.bytes = ~0ULL;
    _action.hard.time = ~0ULL;
    if (Args(this, errh).bind(conf)
	.read("FLAGS", AnyArg(), flags)
	.read("TUNNEL", AnyArg(), tunnel)
	.read("BYTES", IntArg(), _action.hard.bytes)
	.read("TIME", IntArg(), _action.hard.time)
	.consume() < 0)
	return -1;


    // Parse FLAGS

    int mode = -1;
    while (String word = cp_shift_spacevec(flags)) {
	if (word == "PROTOCOL")
	    _action.pfp_proto = 1;
	else if (word == "PORT") {
	    switch (mode) {
	    case IPsec::REMOTE:
		_action.pfp_rport = 1;
		break;
	    case IPsec::LOCAL:
		_action.pfp_lport = 1;
		break;
	    default:
		_action.pfp_rport = 1;
		_action.pfp_lport = 1;
		break;
	    }
	}
	else if (word == "ADDRESS") {
	    switch (mode) {
	    case IPsec::REMOTE:
		_action.pfp_raddr = 1;
		break;
	    case IPsec::LOCAL:
		_action.pfp_laddr = 1;
		break;
	    default:
		_action.pfp_raddr = 1;
		_action.pfp_laddr = 1;
		break;
	    }
	}
	else if (word == "LOCAL")
	    mode = IPsec::LOCAL;
	else if (word == "REMOTE")
	    mode = IPsec::REMOTE;
	else
	    return errh->error("Uknown FLAGS keyword '%s'", word.c_str());
    }

    // Parse TUNNEL

    const ArgContext args(this, errh);

    mode = IPsec::REMOTE;
    while (String addr = cp_shift_spacevec(tunnel)) {
	_action.tunnel_mode = 1;
	if (!IPsecAddressArg().parse(addr, _action.tunnel[mode], args))
	    return errh->error("'%s' is not valid TUNNEL address", addr.c_str());
	mode = IPsec::LOCAL;
    }
    // If both addresses defined, verify that both are either
    // IPv4 or IPv6....
    IPAddress dummy;
    if (mode == IPsec::LOCAL &&
	IP6Address(_action.tunnel[0]).ip4_address(dummy) != 
	IP6Address(_action.tunnel[1]).ip4_address(dummy))
	return errh->error("Both TUNNEL addresses must be of same type -- IPv4 or IPv6");

    // Parse PROPOSALs

    IPsec::Transform **transform;
    _action.proposal.num_transforms = conf.size();
    _action.proposal.transform = transform = new IPsec::Transform *[_action.proposal.num_transforms];
    for (size_t i = 0; i < _action.proposal.num_transforms; ++i) {
	IPsecTransform *tr;
	if (Args(this, errh).bind(conf)
	    .read_mp("PROPOSAL", ElementCastArg("IPsecTransform"), tr)
	    .consume() < 0)
	    return -1;
	// We are in configure -- Transform may not be initialized yet, but
	// the location is already fixed, so it's safe to use that.
	transform[i] = (IPsec::Transform *)&tr->transform();
    }
    return 0;
}


CLICK_ENDDECLS
EXPORT_ELEMENT(IPsecPolicyAction)
