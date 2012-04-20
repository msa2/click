// -*- c-basic-offset: 4 -*-

/*
 * ipsectransform.{cc,hh} -- IPsecTransform
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
#include <click/timer.hh>
#include "ipsecsadata.hh"
#include "ipseckm.hh"

CLICK_DECLS

IPsecKM::IPsecKM() : _ipsec(NULL), _length(0), _key(NULL), _id(0,0), _timer(this)
{
}

IPsecKM::~IPsecKM()
{
    delete[] _key;
}

int IPsecKM::configure(Vector<String> &conf, ErrorHandler *errh)
{
    _ipsec = NULL;
    _trigger = NULL;

    if (Args(this, errh).bind(conf)
	.read_mp("IPSEC", ElementCastArg("IPsec"), _ipsec)
	.read("TRIGGER", ElementCastArg("IPsecSelector"), _trigger)
	.consume() < 0)
	return -1;

    delete[] _key;
    _length = conf.size() / 2;
    _key = new ManualKey[_length];

    for (size_t i = 0; i < _length; ++i) {
	if (Args(this, errh).bind(conf)
	    .read_mp("SELECTOR", ElementCastArg("IPsecSelector"), _key[i].selector)
	    .read_mp("SA", ElementCastArg("IPsecSAData"), _key[i].data)
	    .consume() < 0)
	    return -1;
    }
    return 0;
}

int IPsecKM::initialize(ErrorHandler *errh)
{
    if (!_ipsec)
	return errh->error("No IPsec attached to the Key Manager");
    
    // Attach the key manager to IPsec instance
    int res = _ipsec->attach(*this);
    if (res < 0)
	return errh->error("Failed to attach to IPsec element");
    _id.km = res;

    if (_trigger) {
	_timer.initialize(this);
	_timer.schedule_after(Timestamp(1));
    }
    return 0;
}

// !!! Only need one shot call for this, perhaps using Timer is not
// !!! not he best way?
void IPsecKM::run_timer(Timer *)
{
    if (!_trigger || !_ipsec)
	return;

    const IPsec::Selector &selector = _trigger->selector();
    // For simplicy, just misuse the selector: assume that the val
    // part of each IPsec::Item defines some packet data which we want
    // to use triggering the Acquire.
    for (size_t i = 0; i < selector.length; ++i) {
	++_id.seq;
	_ipsec->trigger_acquire(_id, selector.list[i].val);
    }
}

void IPsecKM::ACQUIRE(IPsec::KMseq id, const IPsec::Association &sa)
{
    // The 'pfp.val' holds the selector information extracted from the
    // packet that triggered this ACQUIRE. The pfp.msk indicates the
    // values are set by PFP flags in PolicyAction.
    IPsec::Match search = sa.pfp.val;

    // Proposal indicates the alternatives from which the negotiation
    // picks one combination.
    const IPsec::Proposal &proposal = sa.proposal();

    // The policy traffic selectors (for IKEv2 TSi TSr) can be read
    // from sa->policy.selector (but keep in mind that "complete"
    // selector includes the "not match" requirement of all preceding
    // policy entries).

    // Information from PolicyAction (sa.policy.action) may be
    // required in some negotiations.

    // The sa.dst indicates the remote end of the security
    // session. The sa.src may be unspecified, indicating that any
    // local address suitable for communicating with dst can be used.

    // In this simple KM example, we look for the predefined manual SA
    // based on the addresses of the SA. Just overrite them in search
    // (this means that you cannot define manual SA based on original
    // packet addresses, but this does leave the original port and
    // protocol information for potential selection criteria).
    search.addr[IPsec::REMOTE] = sa.dst;
    search.addr[IPsec::LOCAL] = sa.src;

    if (!_ipsec)
	return; // Should not happen..

    // Soft lifetime sets the warning treshold for expiry due to
    // age. The values of soft indicate how long before the hard
    // expiry the warning should be generated. The default values
    // (0,0) here give no advance warning...
    const IPsec::LifeTime soft = IPsec::LifeTime();


    // The ONLY way to enter SA into system is as a responce to the
    // ACQUIRE request. This simple KM fakes a "real" key manager,
    // without actually negotiating anything.
    //
    // For outbound SA, actual KM should do:
    //
    // 1. Contact remote end (dst) and establish the session with it,
    //    if such does not yet exist.
    //
    // 2. Negotiate proposal with the remote end and get the SPI for
    //    the outgoing SA.
    //
    // 3. Complete ACQUIRE with negotiated results.

    // Look for matching outbound SA definitions and load all of them
    for (size_t i = 0; i < _length; ++i) {
	const ManualKey &key = _key[i];
	if (!key.selector || !key.data)
	    continue;
	if (!key.selector->selector().match(search))
	    continue;
	if (!proposal.match(key.data->keyinfo()))
	    continue;
	_ipsec->complete_acquire(id, key.data->spi(), key.data->keyinfo(), soft, NULL);
	}

    // For inbound SA, actual KM should do:
    //
    // 1. Contact remote end (dst) and establish the session with it,
    //    if such does not yet exist.
    //
    // 2. Assign SPI for incoming SA (getspi) and pass it to the remote
    //    end along while negotiating.
    //
    // 3. Complete inboud SA with negotiation results.

    // The ACQUIRE gets always gets the sa with MATCH_OUTBOUND set in
    // sa.pfp.val.  Flip this into INBOUD and load any matched SAs
    // (for inbound traffic)
    search.proto = (search.proto & ~IPsec::MATCH_DIRECTION) | IPsec::MATCH_INBOUND;
    for (size_t i = 0; i < _length; ++i) {
	const ManualKey &key = _key[i];
	if (!key.selector || !key.data)
	    continue;
	if (!key.selector->selector().match(search))
	    continue;
	if (!proposal.match(key.data->keyinfo()))
	    continue;
	uint32_t spi_min = key.data->spi();
	uint32_t spi_max = spi_min ? spi_min : ~0U;
	uint32_t spi = _ipsec->getspi(id, spi_min, spi_max);
	if (spi)
	    _ipsec->complete_getspi(id, key.data->spi(),key.data->keyinfo(), soft, NULL);
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IPsecKM)
