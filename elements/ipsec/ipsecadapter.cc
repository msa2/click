// -*- c-basic-offset: 4 -*-

/*
 * ipsecadapter.{cc,hh} -- IPsecAdapter
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
#include <click/packet_anno.hh>
#include "ipsecadapter.hh"
#include "sadatatuple.hh"

CLICK_DECLS

class AdapterContext : public IPsec::TransformContext
{
public:
    ~AdapterContext() {};
    AdapterContext(const void *encr , const void *auth, uint32_t counter, uint8_t o_oowin);
public:
    SADataTuple context;
};

AdapterContext::AdapterContext(const void *encr , const void *auth, uint32_t counter, uint8_t o_oowin)
    : context(SADataTuple(encr, auth, counter, o_oowin))
{
}

IPsec::TransformContext *IPsecAdapter::setup(const IPsec::KeyInfo &info, const IPsec::Association &sa)
{
    if (!transform().match(info))
	return NULL;
    // Only fixed lengths for the keys are supported
    if (info.encr.len != KEY_SIZE*8)
	return NULL;
    if (info.auth.len != KEY_SIZE*8)
	return NULL;
    if (!sa.policy.action.tunnel_mode)
	return NULL; // Only tunnel mode supported
    // And dst address should be IPv4, but we don't test it!

    // !!! need initial replay counter
    // !!! need window size
    return new AdapterContext(info.encr.key, info.auth.key, 1, 32);
}

Packet *IPsecAdapter::simple_action(Packet *p)
{
    IPsec::Association *sa = (IPsec::Association *)IPSEC_SA_DATA_REFERENCE_ANNO(p);
    if (!sa) {
	p->kill();
	return NULL;
    }
    AdapterContext *data = dynamic_cast<AdapterContext *>(sa->context);
    if (!data) {
	p->kill();
	return NULL;
    }

#if SIZEOF_VOID_P == 8
    SET_IPSEC_SA_DATA_REFERENCE_ANNO(p, (uint64_t)&data->context);
#else
    SET_IPSEC_SA_DATA_REFERENCE_ANNO(p, (uint32_t)&data->context);
#endif
    SET_IPSEC_SPI_ANNO(p, sa->spi);
    p->set_dst_ip_anno(sa->dst.in6_u.u6_addr32[3]);
    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IPsecAdapter)
