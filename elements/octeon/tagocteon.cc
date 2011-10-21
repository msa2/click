// -*- mode: c++; c-basic-offset: 4 -*-
/*
 * Copyright (c) 2011-2012 Technical Research Centre of Finland (VTT)
 *
 * Matias.Elo@vtt.fi
 * Markku.Savela@vtt.fi
 */

#include <click/config.h>
#include <click/error.hh>
#include <click/args.hh>
#include <click/router.hh>
#include <click/standard/scheduleinfo.hh>
#include <click/packet_anno.hh>
#include <stdio.h>
#include <unistd.h>

#include "click-octeon/click-octeon.h"
#include "tagocteon.hh"
#include "cvmx-config.h"
#include "cvmx.h"
#include "cvmx-pko.h"
#include "cvmx-helper.h"
CLICK_DECLS


TagOcteon::TagOcteon() : _tag_type(CVMX_POW_TAG_TYPE_ORDERED), _phase(0), _tag(0), _restore(1)
{
}

TagOcteon::~TagOcteon()
{
}

int
TagOcteon::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String type;
    uint32_t tag = _tag;
    uint32_t phase = 0;
    
    if (Args(conf, this, errh)
	.read_mp("TYPE", type)
	.read_p("PHASE", phase)
	.read_p("TAG", tag)
	.read("RESTORE", _restore)
	.complete() < 0)
	return -1;
    if (type) {
	if (type == "ORDERED")
	    _tag_type = CVMX_POW_TAG_TYPE_ORDERED;
	else if (type == "ATOMIC")
	    _tag_type = CVMX_POW_TAG_TYPE_ATOMIC;
	else if (type == "NULL")
	    _tag_type = CVMX_POW_TAG_TYPE_NULL;
	else
	    return errh->error("undefined tag TYPE '%s'", type.c_str());
    }
    _tag = tag;
    click_chatter("%s type=%u, phase=%x, tag=%x restore=%d", declaration().c_str(), (unsigned)_tag_type, (unsigned)phase, (unsigned)_tag, _restore);
    _phase = (phase & 0xFF) << 24;
    return 0;
}

static void tag_switch(const cvmx_pow_tag_info_t current, uint8_t type, uint32_t tag)
{
    if (type == CVMX_POW_TAG_TYPE_NULL) {
	if (current.tag_type != CVMX_POW_TAG_TYPE_NULL &&
	    current.tag_type != CVMX_POW_TAG_TYPE_NULL_NULL)
	    cvmx_pow_tag_sw_null();
    } else if (current.tag != tag || current.tag_type != type) {
	if (current.tag_type == CVMX_POW_TAG_TYPE_NULL) {
	    cvmx_wqe_t *wqp = cvmx_pow_get_current_wqp();
	    cvmx_pow_tag_sw_full(wqp, tag, (cvmx_pow_tag_type_t)type, current.grp);
	} else
	    cvmx_pow_tag_sw(tag, (cvmx_pow_tag_type_t)type);
	cvmx_pow_tag_sw_wait();
    }
}

// simple_action for "pull" usage. The RESTORE option is not available
// for pull case.
Packet *
TagOcteon::simple_action(Packet *p)
{
    const cvmx_pow_tag_info_t current = cvmx_pow_get_current_tag();
    const uint64_t hwbits = _tag ? _tag : cvmx_pow_tag_get_hw_bits(current.tag);
    tag_switch(current, _tag_type, cvmx_pow_tag_compose(_phase, hwbits));
    return p;
}


void
TagOcteon::push(int, Packet* p)
{
    const cvmx_pow_tag_info_t current = cvmx_pow_get_current_tag();
    const uint64_t hwbits = _tag ? _tag : cvmx_pow_tag_get_hw_bits(current.tag);

    tag_switch(current, _tag_type, cvmx_pow_tag_compose(_phase, hwbits));
    output(0).push(p);
    if (_restore)
	tag_switch(cvmx_pow_get_current_tag(), current.tag_type, current.tag);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(TagOcteon)

