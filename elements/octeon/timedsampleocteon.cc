/*
 */

#include <click/config.h>
#include "timedsampleocteon.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/router.hh>

#include "cvmx-config.h"
#include "cvmx.h"
#include "cvmx-pip.h"
#include "cvmx-pko.h"
#include "cvmx-helper.h"

CLICK_DECLS

struct counter
{
    uint32_t high;
    uint32_t low;
};


TimedSampleOcteon::TimedSampleOcteon()
    : _interval(0, Timestamp::subsec_per_sec / 2),
      _count(0), _timer(this)
{
}

TimedSampleOcteon::~TimedSampleOcteon()
{
}

int
TimedSampleOcteon::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (Args(conf, this, errh)
	.read_p("INTERVAL", _interval)
	.complete() < 0)
	return -1;
    return 0;
}

int
TimedSampleOcteon::initialize(ErrorHandler *)
{
    _timer.initialize(this);
    _timer.schedule_after(_interval);
    return 0;
}

void
TimedSampleOcteon::run_timer(Timer *)
{
    WritablePacket *p = WritablePacket::make(128, NULL, sizeof(struct counter) * CVMX_FPA_NUM_POOLS, 0);
    struct counter *d;

    if (!p || !p->data()) {
	click_chatter("Failed to allocate sample packet");
	goto out;
    }

    d = (struct counter *)p->data();
    //click_chatter("packet len=%d\n", p->length());
    for (int pool = 0; pool < CVMX_FPA_NUM_POOLS; ++pool) {
	uint64_t num = cvmx_read_csr(CVMX_FPA_QUEX_AVAILABLE(pool));
	d[pool].high = htonl(num >> 32);
	d[pool].low = htonl(num & 0xFFFFFFFF);
    }
    //click_chatter("sending\n");
    //p->timestamp_anno().assign_now();
    output(0).push(p);
    _count++;
 out:
    _timer.reschedule_after(_interval);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(TimedSampleOcteon)
ELEMENT_MT_SAFE(TimedSampleOcteon)
