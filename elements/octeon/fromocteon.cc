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
#include <click/packet_anno.hh>
#include <click/standard/scheduleinfo.hh>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>

#include "fromocteon.hh"

#include "cvmx-config.h"
#include "cvmx.h"
#include "cvmx-pip.h"
#include "cvmx-pko.h"
#include "cvmx-helper.h"
#include "cvmx-spinlock.h"

CLICK_DECLS

FromOcteon::FromOcteon()
    :
    _count(0), _runs(0), _ipd_port_list(NULL), _port_map_size(0), _port_map(NULL),
    _task(this)
{
    memset(_error, 0, sizeof(_error));
}

FromOcteon::~FromOcteon()
{
    int errors = 0;
    click_chatter("%s [%d] Packets = %lu", declaration().c_str(), cvmx_get_core_num(), (unsigned long)_count);
    click_chatter("%s [%d] Runs = %lu", declaration().c_str(), cvmx_get_core_num(), (unsigned long)_runs);
    for (unsigned int i = 0; i < sizeof(_error) / sizeof(_error[0]); ++i)
	if (_error[i]) {
	    click_chatter("%s [%d] _error[%d] = %lu", declaration().c_str(), cvmx_get_core_num(), i, (unsigned long)_error[i]);
	    ++errors;
	}
    if (errors == 0)
	click_chatter("%s [%d] No errors", declaration().c_str(), cvmx_get_core_num());

    delete [] _ipd_port_list;
    delete [] _port_map;
}

int
FromOcteon::configure(Vector<String> &conf, ErrorHandler *errh)
{
    // Each configuration argument specifies one octeon IPD port and
    // tells this element to route packets from it to the click output
    // port matching the argument position. In addition to these output
    // ports, there is always one extra port, which receives all other
    // packets. Thus, if the argument list is omitted, then all incoming
    // packets go to the click output port 0.

    // WARNING: The port map is allocated based on maximum listed IPD
    // port. This assumes that IPD ports are small numbers (< 64). If
    // this is not true, unnecessarily large array gets allocated.

    _prefetch = 0;
    _prefetch_init = 0;
    if (Args(this, errh).bind(conf).read("PREFETCH", _prefetch).consume() < 0)
	return -1;

    // Save for configured list of ipd_ports for the initialize
    // method where the real mapping can be computed, because the
    // final click ports are known there (but not here).
    _ipd_port_list_size = conf.size();
    _ipd_port_list = new unsigned int [_ipd_port_list_size];
    _port_map_size = 1;
    unsigned int k = 0;
    while (conf.size() > 0) {

	unsigned int port;

	if (Args(this, errh).bind(conf).read_mp("IPD_PORT", port).consume() < 0)
	    return -1;
	if (port+1 >= _port_map_size)
	    _port_map_size = port+2;
	_ipd_port_list[k++] = port;
    }
    return 0;
}

int
FromOcteon::initialize(ErrorHandler *errh)
{
    click_chatter("%s initilize core=%d", declaration().c_str(), cvmx_get_core_num());

    const int ports = noutputs();
    if (ports <= 0)
	return errh->error("at least one output port required");

    // At this point all output Click ports are known. Construct a
    // direct mapping table from ipd_port to Click Port class
    // reference.
    _port_map = new const Port *[_port_map_size];

    // ... map unassigned gaps to default out
    for (unsigned int k = 0; k < _port_map_size; ++k)
	_port_map[k] = &output(ports-1);
    // ... map configured ones to click ports
    for (int k = 0; k < ports; ++k) {
	_port_map[_ipd_port_list[k]] = &output(k);
	click_chatter("%s Mapped IPD Port %d to output [%d]", declaration().c_str(), _ipd_port_list[k], k);
    }
    click_chatter("%s Unmapped IPD Ports go to output [%d]", declaration().c_str(), ports-1);
    // Initialize task to scheduler
    ScheduleInfo::initialize_task(this, &_task, errh);
    return 0;
}

static void long_buf_free(unsigned char *buf, size_t)
{
    delete [] buf;
}

static unsigned
process_work(cvmx_wqe_t *work, const Element::Port &port)
{
    // Synthetic software generated work items are marked with
    // non-zero value in the unused bits of the word0 of the work
    // item. Such work is completely handled within
    // 'click_handle_work'.
    const int type = cvmx_wqe_get_unused8(work);
    if (cvmx_unlikely(type != CLICK_OCTEON_NORMAL)) {
	void *user_data = click_handle_work(work);
	switch (type) {
	case CLICK_OCTEON_PACKET:
	    click_chatter("Handling Packet free");
	    ((Packet *)user_data)->kill();
	    break;
	default:
	    click_chatter("Unknown synthetic work type=%d", type);
	    break;
	}
	return 0;
    }

    const cvmx_pip_wqe_word2_t word2 = work->word2;

    // Check for errored packets, and drop
    if (cvmx_unlikely(word2.snoip.rcv_error)) {
	const unsigned code = word2.snoip.err_code;
	cvmx_helper_free_packet_data(work);
	cvmx_fpa_free_nosync(work, click_octeon_wqe_pool, 0);
	return code;
    }

    CVMX_PREFETCH_NOTL2(&port, 0);

    const click_octeon_pool_t data = {long_buf_free, cvmx_wqe_get_len(work)};

    // Each alternative of the following if statement must initialize
    // every one of the following variables
    unsigned char *buf;
    uint16_t offset;
    const click_octeon_pool_t *pool;

    if (word2.s.bufs == 0) {
	// The packet data is within the work entry. Construct the
	// Click Packet using the work queue entry as a buffer
	// space.
	pool = &click_octeon_pool_info[click_octeon_wqe_pool];
	CVMX_PREFETCH0(pool);
	offset = offsetof(cvmx_wqe_t, packet_data);
	if (cvmx_likely(!word2.s.not_IP)) {
	    // ASSUMES PIP_IP_OFFSET == 2! (16 BYTES)
	    offset += 16 - word2.s.ip_offset + (word2.s.is_v6 ? 0 : 4);
	}
	buf = (unsigned char *)work;
    } else if (cvmx_likely(word2.s.bufs == 1)) {
	// The packet data is in single buffer allocated from a
	// FPA pool by Octeon. Construct the Click Packet using
	// this as a buffer space.
	const cvmx_buf_ptr_t ptr = work->packet_ptr;
	const uint64_t addr = ((ptr.s.addr >> 7) - ptr.s.back) << 7;

	pool = &click_octeon_pool_info[ptr.s.pool];
	CVMX_PREFETCH0(pool);
	offset = ptr.s.addr - addr;
	buf = (unsigned char *)cvmx_phys_to_ptr(addr);
    } else {
	// The packet data is in multiple buffers allcoated from
	// FPA pool. The Click requires that the packet data is in
	// single contiguous buffer. Allocate a new sufficiently
	// large Click Packaet and copy the data there.
	
	// NOTE: This branch has not been tested, as the default
	// size of the FPA data buffer is larger than MTU of the
	// currently used link layer, and multiple buffers never
	// appear...?
	
	cvmx_buf_ptr_t segment_ptr = work->packet_ptr;
	click_chatter("Untested bufs==%u detected, len=%d", (unsigned int)word2.s.bufs, data.size);
	pool = &data;
	offset = 0;
	buf = new unsigned char [data.size];
	if (!buf) {
	    cvmx_helper_free_packet_data(work);
	    cvmx_fpa_free_nosync(work, click_octeon_wqe_pool, 0);
	    return 0;
	}

	int segments = word2.s.bufs;
	int to_copy = data.size;
	int copied = 0;
	while (segments--) {
	    cvmx_buf_ptr_t next_ptr = *(cvmx_buf_ptr_t *)cvmx_phys_to_ptr(segment_ptr.s.addr-8);
	    // Octeon Errata PKI-100: The segment size is
	    // wrong. Until it is fixed, calculate the segment
	    // size based on the packet pool buffer size. When it
	    // is fixed, the following line should be replaced
	    // with this one: int segment_size =
	    // segment_ptr.s.size
	    
	    int segment_size = CVMX_FPA_PACKET_POOL_SIZE -
		(segment_ptr.s.addr - (((segment_ptr.s.addr >> 7) - segment_ptr.s.back) << 7));
	    if (segment_size > to_copy)
		segment_size = to_copy;
	    memcpy(buf + copied, (void *)cvmx_phys_to_ptr(segment_ptr.s.addr), segment_size);
	    to_copy -= segment_size;
	    copied += segment_size;
	    segment_ptr = next_ptr;
	}

	// In NO_WPTR mode, this does not release the first buffer,
	// but it will be released below, when the work gets released.
	cvmx_helper_free_packet_data(work);
    }

    // Only the WQE part is unreleased. The payload/data has either
    // been already released or transformed into (buf, destructor).
    WritablePacket *p = Packet::make(buf, pool->size, pool->destructor);
    if (cvmx_unlikely(!p)) {
	pool->destructor(buf, pool->size);
	cvmx_fpa_free_nosync(work, click_octeon_wqe_pool, 0);
	return 0;
    }
    p->pull(offset);
    p->take(pool->size - offset - data.size); // make some tailroom available...

    // Setting packet type	
    if (cvmx_unlikely(word2.s.is_bcast))
	p->set_packet_type_anno(Packet::BROADCAST);
    else if (cvmx_unlikely(word2.s.is_mcast))
	p->set_packet_type_anno(Packet::MULTICAST);
    //p->timestamp_anno().assign_now(); // Timestamp
    p->set_mac_header(p->data());
    port.push(p);
    
    // The 'buf' == work, when packet is short and fully included in
    // the WQE; or when NO_WPTR mode is enabled and all data is in the
    // first segment. In such case the work cannot be released here.
    if (buf != (unsigned char *)work)
	cvmx_fpa_free_nosync(work, click_octeon_wqe_pool, 0);
    return 0;
}

void FromOcteon::error_count(unsigned code)
{
    if (code < sizeof(_error) / sizeof(_error[0]))
	++_error[code];
    // Accumulate all errors into [0].  The error code itself
    // is never 0.
    ++_error[0];
}

bool
FromOcteon::run_task(Task *) // Try to receive packet from Octeon port
{
    counter_t count = 0;
    cvmx_wqe_t *work;

    ++_runs;
    if (!_prefetch) {
	while ((work = cvmx_pow_work_request_sync(CVMX_POW_WAIT)) != NULL) {
	    // work is read only, try to skip L2 cache totally...
	    CVMX_PREFETCH_NOTL2(work, 0);

	    const unsigned result = process_work(work, map_port(cvmx_wqe_get_port(work)));
	    if (cvmx_unlikely(result > 0))
		error_count(result);
	    if (++count > 200)
		break;
	}
    }  else {
	// Prefetch is always active, except on first call, where it needs to be started
	if (cvmx_unlikely(!_prefetch_init)) {
	    _prefetch_init = 1;
	    cvmx_pow_work_request_async_nocheck(FROMOCTEON_SCR_WORK, CVMX_POW_WAIT);
	}
	work = NULL;
	do {
	    cvmx_wqe_t *prefetch_work = cvmx_pow_work_response_async(FROMOCTEON_SCR_WORK);
	    cvmx_pow_work_request_async_nocheck(FROMOCTEON_SCR_WORK, CVMX_POW_WAIT);
	    if (cvmx_likely(prefetch_work))
		// work is read only, try to skip L2 cache totally...
		CVMX_PREFETCH_NOTL2(prefetch_work, 0);
	    if (cvmx_likely(work)) {
		const unsigned result = process_work(work, map_port(cvmx_wqe_get_port(work)));
		if (cvmx_unlikely(result > 0))
		    error_count(result);
		++count;
	    }
	    work = prefetch_work;
	} while (work);
    }
    _task.fast_reschedule();
    // Returns TRUE, if any work done.
    _count += count;
    return count > 0;
}

String
FromOcteon::read_handler(Element* e, void *thunk)
{
    FromOcteon* fd = static_cast<FromOcteon*>(e);
    if (thunk == (void *) 0)
	return String(fd->_error[0]);
    else
	return String(fd->_count);
}

int
FromOcteon::write_handler(const String &, Element *e, void *, ErrorHandler *)
{
    FromOcteon* fd = static_cast<FromOcteon*>(e);
    fd->_count = 0;
    memset(fd->_error, 0, sizeof(fd->_error));
    return 0;
}

void
FromOcteon::add_handlers()
{
    add_read_handler("drops", read_handler, (void *) 0);
    add_read_handler("count", read_handler, (void *) 2);
    add_write_handler("reset_counts", write_handler, 0, Handler::BUTTON);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(FromOcteon)
