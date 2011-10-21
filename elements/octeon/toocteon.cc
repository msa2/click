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
#include "toocteon.hh"
#include "cvmx-config.h"
#include "cvmx.h"
#include "cvmx-pko.h"
#include "cvmx-helper.h"

CLICK_DECLS

ToOcteon::ToOcteon()
    : _copied(0), _count(0), _dropped(0)
{
}

ToOcteon::~ToOcteon()
{
    click_chatter("%s [%d] %lu packets\n", declaration().c_str(), cvmx_get_core_num(), _count);
    click_chatter("%s [%d] %lu packets needed copying\n", declaration().c_str(), cvmx_get_core_num(), _copied);
    click_chatter("%s [%d] %lu packets dropped\n", declaration().c_str(), cvmx_get_core_num(), _dropped);
}

int
ToOcteon::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String locking;

    if (Args(conf, this, errh)
	.read_mp("PORT", _port)
	.read_p("LOCKING", locking)
	.complete() < 0)
	return -1;

    // Verify that the port exists on some interface
    const int interfaces = cvmx_helper_get_number_of_interfaces();
    for (_interface = 0; _interface < interfaces; ++_interface) {
	const int port_min = cvmx_helper_get_ipd_port(_interface, 0);
	const int port_max = port_min + cvmx_helper_ports_on_interface(_interface);
	if (_port >= port_min && _port < port_max)
	    break;
    }
    if (_interface >= interfaces)
	return errh->error("Port %d does not exist on any interface", _port);

    if (locking) {
	if (locking == "ATOMIC_TAG")
	    _pko_locking = CVMX_PKO_LOCK_ATOMIC_TAG;
	else if (locking == "CMD_QUEUE")
	    _pko_locking = CVMX_PKO_LOCK_CMD_QUEUE;
	else if (locking == "NONE")
	    _pko_locking = CVMX_PKO_LOCK_NONE;
	else
	    return errh->error("undefined locking '%s'", locking.c_str());
    } else
	_pko_locking = CVMX_PKO_LOCK_CMD_QUEUE;


    click_chatter("%s(%d) is on interface %d\n", declaration().c_str(), _port, _interface);
    return 0;
}

int
ToOcteon::initialize(ErrorHandler *)
{
    // If not LOCKLESS, the queue is defined by port only
    _queue = cvmx_pko_get_base_queue(_port);
    return 0;
}

void
ToOcteon::push(int, Packet* p)
{
    const unsigned bytes = p->length();
    const unsigned char *data = p->data();
    const int pool = click_octeon_pool(p->buffer_destructor());
    const cvmx_pko_lock_t pko_locking = static_cast<cvmx_pko_lock_t>(_pko_locking);
#if CVMX_ENABLE_PKO_LOCKLESS_OPERATION
    // In this mode, the queue depends on core number.
    const int queue =
	pko_locking != CVMX_PKO_LOCK_NONE ? _queue : cvmx_pko_get_base_queue_per_core(_port, cvmx_get_core_num());
#else
    const int queue = _queue;
#endif 
    cvmx_pko_command_word0_t pko_command;
    pko_command.u64 = 0;
    pko_command.s.total_bytes = bytes;
    pko_command.s.segs = 1;
    
    // Setting .n2 causes a huge perfomance hit on 10Gb interface with
    // short packets if len > 90. Possibly might be useful for much
    // longer packets, but as the optimal treshold is not known at
    // this point, don't set .n2!...

    //pko_command.s.n2 = 1;

    cvmx_buf_ptr_t packet_ptr;
    packet_ptr.u64 = 0;

    if (cvmx_unlikely(data == NULL || bytes == 0 || queue < 0)) {
	// Drop invalid Packets
	click_chatter("Push: Invalid Packet (length=%u)%s queue=%d core=%u!",
		      bytes, data ? "" : " data==NULL", queue, (unsigned)cvmx_get_core_num());
	goto drop;
    }

    // WARNING: In unlikely case that data is not XKPHYS address, the
    // following generates "garbage" packet_ptr, which is not used by
    // subsequent code (pool = -1 and result of cvmx_ptr_to_phys is
    // not valid).
    packet_ptr.s.addr = cvmx_ptr_to_phys((void *)data);
    packet_ptr.s.pool = pool;
    packet_ptr.s.size = bytes;
    packet_ptr.s.back = (data - p->buffer()) >> 7;

    if (cvmx_unlikely(pool < 0 || p->shared())) {
	// Packet data is shared or not allocated from Octeon pool,
	// the buffers cannot be released by octeon.
	void *new_data;
	const cvmx_addr_t addr = {(uint64_t)data};
	if (addr.sva.R == CVMX_MIPS_SPACE_XKPHYS) {
	    // Address in XKPHYS are, we can pass it to PKO, but cannot release
	    // the memory within PKO....
	    cvmx_wqe_t *work = (cvmx_wqe_t *)click_make_work(CLICK_OCTEON_PACKET, p);
	    if (!work)
		goto drop;
	    click_chatter("Don't copy: length=%u data=%llx", bytes, (uint64_t)data);
	    pko_command.s.dontfree = 1;
	    pko_command.s.rsp = 1;
	    pko_command.s.wqp = 1;
	    cvmx_pko_send_packet_prepare(_port, queue, pko_locking);
	    if (cvmx_pko_send_packet_finish3(_port, queue, pko_command, packet_ptr,
					     cvmx_ptr_to_phys(work), pko_locking) !=  CVMX_PKO_SUCCESS) {
		// Buffers are still attached to to p, just release the internal work item here.
		click_chatter("Push: pko-send3 failed length=%u", bytes);
		click_handle_work(work);
		goto drop;
	    }
	    return;
	}
	// Address not in XKPHYS area, need to copy and allocate a buffer
	if (bytes > CVMX_FPA_PACKET_POOL_SIZE) {
	    click_chatter("Push: length=%u from pool=%d is too large for octeon buffer (%u)!\n",
			  bytes, pool, CVMX_FPA_PACKET_POOL_SIZE);
	    goto drop;
	} else if ((new_data = cvmx_fpa_alloc(CVMX_FPA_PACKET_POOL)) == NULL) {
	    click_chatter("Push: length=%u from pool=%d failed allocating from FPA poo!", bytes, pool);
	    goto drop;
	}
	memcpy(new_data, data, bytes);
	packet_ptr.s.pool = CVMX_FPA_PACKET_POOL;
	packet_ptr.s.addr = cvmx_ptr_to_phys(new_data);
	packet_ptr.s.back = 0;
	++_copied;
    } else {
	p->reset_buffer(); // Detach buffer from packet...
    }

    // Send the packet 

    cvmx_pko_send_packet_prepare(_port, queue, pko_locking);
    if (cvmx_unlikely(cvmx_pko_send_packet_finish
		      (_port, queue, pko_command, packet_ptr, pko_locking) != CVMX_PKO_SUCCESS)) {
	// Failed to send the command. Release the buffer. The buffer
	// has already been detached from the packet or is a temporary
	// allocation -- get buffer address and pool from the actual
	// packet_ptr.
	const uint64_t addr = ((packet_ptr.s.addr >> 7) - packet_ptr.s.back) << 7;
	click_chatter("Push: pko-send failed length=%u", bytes);
	cvmx_fpa_free(cvmx_phys_to_ptr(addr), packet_ptr.s.pool, 0);
	goto drop;
    }
    //++_count; // this seems to be "heavy" operation??
    p->kill();
    return;
drop:
    // Packet output failed for some reason
    ++_dropped;
    p->kill();
}


String
ToOcteon::read_param(Element *, void *)
{
    return String();
}

int
ToOcteon::write_param(const String &, Element *, void *,
			   ErrorHandler *)
{
    return 0;
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(ToOcteon)

