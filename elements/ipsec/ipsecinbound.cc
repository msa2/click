// -*- c-basic-offset: 4 -*-

/*
 * ipsecinbound.{cc,hh} -- IPsecInbound
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
#include "ipsec.hh"
#include "ipsecinbound.hh"

CLICK_DECLS

IPsecInbound::IPsecInbound() : _ipsec(NULL)
{
}

int IPsecInbound::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (Args(conf, this, errh)
	.read_mp("IPSEC", ElementCastArg("IPsec"), _ipsec)
	.complete() < 0)
	return -1;
    return 0;
}

int IPsecInbound::initialize(ErrorHandler *errh)
{
    if (!_ipsec)
	return errh->error("No IPsec attached to the IPsecInbound");
    
    // Attach the inbound processing to the IPsec

    if (!_ipsec->attach(this))
	return errh->error("Failed to attach to IPsec element");
    return 0;
}

void IPsecInbound::push(int, Packet *p)
{
    const unsigned char *nh = p->network_header();
    if (!nh) {
	p->kill();
	return;
    }
    unsigned hlen;
    uint8_t proto;
    const unsigned ipv = *nh & 0xF0;
    if (ipv == 0x40) {
	// Check IPv4
	const click_ip &ip4 = reinterpret_cast<const click_ip &>(*nh);
	hlen = (*nh & 0xF) << 2;
	proto = ip4.ip_p;
    } else if (ipv == 0x60) {
	// Check IPv6
	const click_ip6 &ip6 = reinterpret_cast<const click_ip6 &>(*nh);
	hlen = 40;
	proto = ip6.ip6_ctlun.ip6_un1.ip6_un1_nxt;
    } else {
	// Invalid IP packet. DISCARD
	p->kill();
	return;
    }
    // Locate the IPsec header (need to skip potential extension headers)
    const unsigned char *h = nh;
    do {
	h += hlen;

	// !!! verify h does not point beyond packet data

	switch (proto) {
	case 0: // Hop-by-Hop option
	case 43: // IPv6 Routing Header
	case 60: // IPv6 Destination Options
	    // h+2 must be within packet
	    proto = *h;
	    hlen = (h[1]+1) * 8;
	    break;
	case 50: // Encapsulating Security Paylod
	    // SPI is at h
	    goto done;
	case 51: // Authentication Header
	    h += 4; // SPI is at h+4
	    goto done;
	default:
	    // Not IPsec, forward to port 0
	    checked_output_push(0, p);
	    return;
	}
    } while (1);
  done:
    uint32_t spi = h[0] << 24 | h[1] << 16 | h[2] << 8 | h[3];
    IPsec::Association *sa = _ipsec->lookup(spi);
    if (!sa) {
	click_chatter("IPsecInbound SA not found");
	p->kill();
	return;
    }
    SET_IPSEC_SA_DATA_REFERENCE_ANNO(p, (uint64_t)sa);
    checked_output_push(sa->click_port, p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IPsecInbound)
