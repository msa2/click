// -*- mode: c++; c-basic-offset: 4 -*-

/*
 * Copyright (c) 2011 Technical Research Centre of Finland (VTT)
 *
 * Matias.Elo@vtt.fi
 */
#ifndef CLICK_FROMOCTEON_USERLEVEL_HH
#define CLICK_FROMOCTEON_USERLEVEL_HH
#include <click/element.hh>
#include <click/task.hh>

CLICK_DECLS

/*
 * =c
 * FromOcteon([PREFETCH,][IPD_PORT,IPD_PORT,...])
 * =s octeon
 * Receive incoming packets from Octeon
 *
 * =d
 * Receive incoming packets from octeon from any port, setup them as
 * Click packets, and output them to the corresponding click port.
 *
 * "PREFETCH 1" instructs FromOcteon to prefetch the next work item
 * while processing the previous one. This mode has limited
 * usefulness, as the core gets tagged with the new work in the middle
 * of the processing of the previous work. Suitable only for very
 * simple "pass through" configurations.
 *
 * Each specified IPD_PORT maps packets from that port to
 * corresponding output port (the first specified goes to 0, next one
 * to 1, etc). The total number of output ports is the number of
 * configuration arguments + 1. All packets from unmapped IPD ports go
 * the the last port.
 *
 * Without any configuration parameters (IPD_PORT), pushes all
 * received packets from any port to output port 0.
 *
 * = ToOcteon, TagOcteon
 */

class FromOcteon : public Element { public:

    FromOcteon();
    ~FromOcteon();

    const char *class_name() const	{ return "FromOcteon"; }
    const char *port_count() const	{ return "0/-"; }
    const char *processing() const	{ return "h/h"; }

    int configure(Vector<String> &conf, ErrorHandler *errh);
    int initialize(ErrorHandler *);
    void add_handlers();

    bool run_task(Task *);

    inline const Port &map_port(unsigned ipd_port) const;
    void error_count(unsigned code);

public:
#if HAVE_INT64_TYPES
    typedef uint64_t counter_t;
#else
    typedef uint32_t counter_t;
#endif
    counter_t _count, _runs;
    counter_t _error[32]; // Error counters

    // IPD port mapping information
    unsigned int *_ipd_port_list;
    unsigned int _ipd_port_list_size;

    unsigned int _port_map_size;
    const Port **_port_map;
    bool _prefetch, _prefetch_init;

    Task _task;

    static String read_handler(Element*, void*);
    static int write_handler(const String&, Element*, void*, ErrorHandler*);
};

/*
 * Map ipd_port into click Port reference
 */
inline const Element::Port&
FromOcteon::map_port(unsigned ipd_port) const
{
    return *_port_map[ipd_port < _port_map_size ? ipd_port : _port_map_size];
}

CLICK_ENDDECLS
#endif
