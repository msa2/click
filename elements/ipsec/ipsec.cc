// -*- c-basic-offset: 4 -*-

/*
 * ipsec.{cc,hh} -- IPsec
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
#include <click/config.h>
#include <click/args.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <click/ipaddress.hh>
#include <click/ip6address.hh>
#include "ipsec.hh"
#include "ipsecselector.hh"
#include "ipsecpolicyaction.hh"
#include "ipsectransform.hh"

CLICK_DECLS

class Mutex {
public:
    inline Mutex(volatile uint32_t &lock) : _lock(lock) {
#if HAVE_MULTITHREAD
	while (atomic_uint32_t::swap(_lock, 1) == 1)
	    /* do nothing */;
#endif
    }
    inline ~Mutex() { _lock = 0; }
private:
    volatile uint32_t &_lock;
};

IPsec::Policy::~Policy()
{
    while (list) {
	PolicyItem *p = list;
	list = list->next;
	delete p;
    }
}

IPsec::PolicyItem *IPsec::Policy::match(const Match &search) const
{
    for (IPsec::PolicyItem *p = list; p != NULL; p = p->next)
	if (p->selector.match(search))
	    return p;
    return NULL;
}

void IPsec::Policy::add(PolicyItem *item)
{
    if (item) {
	// !!! REVISIT: This is not multithread safe while system is
	// !!! running. Currently Add should be called only in
	// !!! configure! Dynamic policy change not supported yet.
	*_last = item;
	_last = &item->next;
    }
}

class KM {
public:
    KM(IPsec::KeyManager &km, KM *next);

    IPsec::KeyManager &mgr;
    KM *next;
};

KM::KM(IPsec::KeyManager &km, KM *next) : mgr(km), next(next)
{
}

IPsec::Association::Association(KMseq kmid, const PolicyItem &policy,
		    const click_in6_addr &src,
		    const click_in6_addr &dst)
    : kmid(kmid), policy(policy), src(src), dst(dst), lock(0), context(NULL)
{
    spi = 0;
    state = SA_LARVAL;
    age = LifeTime();
    soft = LifeTime();
    next = NULL;
}

IPsec::Association::~Association()
{
    delete context;
    delete[] narrowed.list;
}

bool IPsec::Association::init_pipe(const Element *e, const KeyInfo &key)
{
    if (!e)
	return false;

    delete context;

    // Locate the pipe lines (click port numbers) matching the algorithm
    int port = e->noutputs();
    while (--port >= 0) {
	IPsecTransform *tr = (IPsecTransform *)e->output(port).element()->cast("IPsecTransform");
	if (!tr)
	    continue;
	context = tr->setup(key, *this);
	if (context) {
	    // Pipeline successfully initialized
	    click_port = port;
	    return true;
	}
    }
    return false;
}

IPsec::IPsec() : _ipsec_inbound(NULL), _inbound_lock(0), _kmgr(0), _kmid(0), _seq(0)
{
    // !!! Clear _inbound[] array (or make size configurable)
    for (size_t i = 0; i < _isize; ++i)
	_inbound[i] = NULL;
}

IPsec::~IPsec()
{
}

int IPsec::configure(Vector<String> &conf, ErrorHandler *errh)
{
    // Parse optional initial policy

    size_t plen = conf.size();

    const ArgContext args = ArgContext(this, errh);
    for (size_t i = 0; i < plen; ++i) {
	IPsecSelector *selector;
	IPsecPolicyAction *action;
	
	if (!ElementCastArg("IPsecSelector").parse(cp_shift_spacevec(conf[i]), selector, args) ||
	    !ElementCastArg("IPsecPolicyAction").parse(conf[i], action, args))
	    return -1;
	_policy.add(new PolicyItem(selector->selector(), action->action()));
    }
    return 0;
}

int IPsec::initialize(ErrorHandler *)
{
#if HAVE_IP6
    // Just debugging output...
    for (const PolicyItem *p = _policy.list; p != NULL; p = p->next) {
	for (size_t k = 0; k < p->selector.length; ++k) {
	    const Item &s = p->selector.list[k];
	    click_chatter("CONF PROTOCOL %d %d LOCAL  %s#%x  %s#%x REMOTE %s#%x  %s#%x",
			  (int)(s.val.proto & 0xFF),
			  (int)(s.msk.proto & 0xFF),
			  IP6Address(s.val.addr[LOCAL]).unparse().c_str(),
			  (int)s.val.port[LOCAL],
			  IP6Address(s.msk.addr[LOCAL]).unparse().c_str(),
			  (int)s.msk.port[LOCAL],
			  IP6Address(s.val.addr[REMOTE]).unparse().c_str(),
			  (int)s.val.port[REMOTE],
			  IP6Address(s.msk.addr[REMOTE]).unparse().c_str(),
			  (int)s.msk.port[REMOTE]);
	}
    }
#endif
    return 0;
}

// TODO - Dynamic policy update
int IPsec::policy_clear()
{
    return 0;
}

// TODO - Dynamic policy update
int IPsec::policy_add(unsigned, const Selector &, const PolicyAction &)
{
    return 0;
}

void IPsec::add_inbound(Association &sa)
{
    const unsigned index = sa.spi % _isize;
    sa.next = _inbound[index];
    _inbound[index] = &sa;
}

IPsec::Association *IPsec::lookup(const click_in6_addr &dst,
				  const click_in6_addr &src,
				  const Match &search,
				  IPsec::Association *sa) const
{
    for (; sa != NULL; sa = sa->next)
	if (dst.in6_u.u6_addr64[1] == sa->dst.in6_u.u6_addr64[1] &&
	    dst.in6_u.u6_addr64[0] == sa->dst.in6_u.u6_addr64[0] &&
	    src.in6_u.u6_addr64[1] == sa->src.in6_u.u6_addr64[1] &&
	    src.in6_u.u6_addr64[0] == sa->src.in6_u.u6_addr64[0] &&
	    sa->pfp.match(search) &&
	    sa->narrowed.match(search))
	    break;
    return sa;
}

IPsec::Association *IPsec::lookup(KMseq kmid) const
{
    // Brute force search now...
    for (const PolicyItem *p = _policy.list; p != NULL; p = p->next)
	for (Association *sa = p->sa; sa != NULL; sa = sa->next)
	    if (kmid.km == sa->kmid.km && kmid.seq == sa->kmid.seq)
		return sa;
    return NULL;
}

IPsec::Association *IPsec::lookup(uint32_t spi) const
{
    for (Association *sa = _inbound[spi % _isize];  sa != NULL; sa = sa->next)
	if (sa->spi == spi)
	    return sa;
    return NULL;
}

IPsec::Association *IPsec::start_acquire(PolicyItem &policy,
					 KMseq id,
					 const Match &search,
					 const click_in6_addr &src,
					 const click_in6_addr &dst)
{
    static const click_in6_addr addr_mask = {
	{{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}},
    };

    Association *sa;
    {
	Mutex enter(policy.lock);

	// Now that we have a lock, check again in case the
	// required sa appeared
	sa = lookup(dst, src, search, policy.sa);
	if (sa)
	    return sa;

	// Suitable SA does not exist, really start the ACQUIRE process

	sa = new Association(id, policy, src, dst);
	if (!sa) {
	    click_chatter("Out of memory in SA allocation");
	    return NULL;
	}

	sa->spi = 0; // SA_LARVAL with SPI==0 is "EGG"
	
	// If any of the PFP-flags present, need to create
	// specific selector from search.
	memset(&sa->pfp, 0, sizeof(sa->pfp));
	sa->pfp.val.proto = 0;
	if (policy.action.pfp_laddr) {
	    sa->pfp.val.addr[LOCAL] = search.addr[LOCAL];
	    sa->pfp.msk.addr[LOCAL] = addr_mask;
	}
	if (policy.action.pfp_raddr) {
	    sa->pfp.val.addr[REMOTE] = search.addr[REMOTE];
	    sa->pfp.msk.addr[REMOTE] = addr_mask;
	}
	if (policy.action.pfp_lport) {
	    sa->pfp.val.port[LOCAL] = search.port[LOCAL];
	    sa->pfp.msk.port[LOCAL] = 0xFFFF;
	}
	if (policy.action.pfp_rport) {
	    sa->pfp.val.port[REMOTE] = search.port[REMOTE];
	    sa->pfp.msk.port[REMOTE] = 0xFFFF;
	}
	if (policy.action.pfp_proto) {
	    sa->pfp.val.proto = search.proto;
	    sa->pfp.msk.proto = 0xFF;
	}
	sa->soft = policy.action.hard;
	sa->narrowed.length = 0;
	sa->narrowed.list = NULL;

	// !!! Should set a default life timer which expires and
	// !!! kills the larval SA, if it is not completed by
	// !!! complete_acquire within time limit.
    
	// !!! This operation should be safe, even if another
	// !!! thread is reading the policy at same time..
	sa->next = policy.sa;
	policy.sa = sa;
    }

    // Note: this is outside policy.lock
    for (KM *km = _kmgr; km != NULL; km = km->next) {
	km->mgr.ACQUIRE(id, *sa);
    }
    return sa;
}

void IPsec::push(int port, Packet *p)
{
    static const Match zero = {
	// raddr = default to IPv4 mapped format
	{
	    0, // proto = 0
	    {0,0},
	    // laddr = default to IPv4 mapped format
	    {{{{0,0,0,0,0,0,0,0,0,0,0xFF,0xFF,0,0,0,0}}},
	     {{{0,0,0,0,0,0,0,0,0,0,0xFF,0xFF,0,0,0,0}}}},
	},
    };


    Association *sa = (Association *)IPSEC_SA_DATA_REFERENCE_ANNO(p);
    if (sa) {
	if (port == 0) {
	    // Outbound Packet annotated with IPsec Association. Assume it
	    // is valid and just pass through. Trust whomever has set the
	    // the annotation, knows the SA is correct to use -- "IPsec
	    // fast path" ...
	    checked_output_push(sa->click_port, p);
	    return;
	}
	// Inbound Packet annotated with something. If the pipeline is
	// "old style", this is actually SADataTuple, which is not right
	// for us. UGLY HACK FOR NOW: Assume SPI annotation is still valid
	// and get the real SA using it.
	sa = lookup(IPSEC_SPI_ANNO(p));
	// !!! REVISIT: Invent better way to deal with this!
    }
    const unsigned char *nh = p->network_header();
    Match search = zero;

    if (!nh || port > 1 || port < 0) {
	// The network header must be present for now. DISCARD
	checked_output_push(PORT_DISCARD, p);
	return;
    }

    // Where to put src addr/port from the packet: outbout (port==0)
    // -> LOCAL, inboud (port==1) -> REMOTE (and dst addr/port go to
    // !flip).
    const int flip = port ? REMOTE : LOCAL;
    search.proto = port ? MATCH_INBOUND : MATCH_OUTBOUND;

    // Extract remote (= dst) and local (= src) addresses from the
    // IP header of the packet.
    unsigned hlen;
    uint8_t proto;
    const unsigned ipv = *nh & 0xF0;
    if (ipv == 0x40) {
	// Extract IPv4 selector information
	const click_ip &ip4 = reinterpret_cast<const click_ip &>(*nh);
	// Load remote and local as IPv4 mapped addresses
	search.addr[flip].in6_u.u6_addr32[3] = ip4.ip_src.s_addr;
	search.addr[!flip].in6_u.u6_addr32[3] = ip4.ip_dst.s_addr;
	hlen = (*nh & 0xF) << 2;
	proto = ip4.ip_p;
    } else if (ipv == 0x60) {
	// Extract IPv6 selector information
	const click_ip6 &ip6 = reinterpret_cast<const click_ip6 &>(*nh);
	search.addr[flip] = ip6.ip6_src;
	search.addr[!flip] = ip6.ip6_dst;
	hlen = 40;
	proto = ip6.ip6_ctlun.ip6_un1.ip6_un1_nxt;
    } else {
	// Invalid IP packet. DISCARD
	checked_output_push(PORT_DISCARD, p);
	return;
    }

    // Locate the transport header (cannot use p->transport_header, because
    // we cannot reliably decide what the protocol is without going through
    // the possible chain of extension headers...

    // !!! TODO: OPAQUE vs. not available?
    const unsigned char *h = nh;
    do {
	h += hlen;

	// Check that h is within packet data (only h[0..3] needed in
	// below, thus -4)
	if (h < p->data() || h >= p->end_data() - 4)
	    break;

	switch (proto) {
	case 0: // Hop-by-Hop option
	case 43: // IPv6 Routing Header
	case 60: // IPv6 Destination Options
	    // h+2 must be within packet
	    proto = *h;
	    hlen = (h[1]+1) * 8;
	    break;
	case 1: // Internet Control Message Protocol (ICMP v4)
	case 58: // Internet Control Message Protocol for IPv6 (ICMPv6)
	    // h+1 must be within packet
	    // Always in local port (whether inbound or outbound)
	    search.port[LOCAL] = (h[0] << 8) | h[1];
	    search.proto |= MATCH_TYPE;
	    goto done;
	case 6: // Transmission Control Protocol (TCP)
	case 17: // User Datagram Protcol (UDP)
	case 132: // Stream Control Transmission Protocol (SCTP)
	case 136: // Lightweight User Datagaram Protocol (UDPLite)
	    // h+3 must be within packet
	    search.port[flip] = (h[0] << 8) | h[1];
	    search.port[!flip] = (h[2] << 8) | h[3];
	    search.proto |= MATCH_PORTS;
	    goto done;
	case 44: // IPv6 Fragment Header
	    goto done;
	case 50: // Encapsulating Security Paylod
	    goto done;
	case 51: // Authentication Header
	    goto done;
	case 135: // Mobility Header
	    // h+2 must be within packet
	    // Always in local port (whether inbound or outbound)
	    search.port[LOCAL] = h[2] << 8; // Host order!!
	    search.proto |= MATCH_TYPE;
	    goto done;
	default:
	    // Port selectors are not available
	    goto done;
	}
    } while (1);
  done:
    // Use current proto as transport protocol
    search.proto |= proto;

#if 0 // or HAVE_IP6
    // debugging chatter
    click_chatter("PACKET PROTOCOL %d LOCAL  %s#%x REMOTE %s#%x",
		  (int)(search.proto & 0xFF),
		  IP6Address(search.addr[LOCAL]).unparse().c_str(),
		  (int)search.port[LOCAL],
		  IP6Address(search.addr[REMOTE]).unparse().c_str(),
		  (int)search.port[REMOTE]);
#endif

    if (port && sa) {
	// Inbound processing differs, if packet has association
	// annotation. Verify that the packet matches the applied
	// SA.

	// !!! For now, do the brute force policy search and check
	// !!! that the applied SA is associated with this policy.
	PolicyItem *policy = _policy.match(search);
	if (policy == NULL) {
	    click_chatter("Packet denied by the policy");
	    checked_output_push(PORT_DISCARD, p);
	    return;
	}
	if (policy != &sa->policy) {
	    click_chatter("Applied SA spi=%u does not match the policy", sa->spi);
	    checked_output_push(PORT_DISCARD, p);
	    return;
	}
	SET_IPSEC_SA_DATA_REFERENCE_ANNO(p, (uint64_t)0);
	checked_output_push(port, p);
	return;
    }

    PolicyItem *policy = _policy.match(search);
    if (policy == NULL) {
	// Policy does not match the packet, discard
	checked_output_push(PORT_DISCARD, p);
	return;
    }

    if (policy->action.proposal.num_transforms == 0) {
	// No transforms specified, BYPASS
	checked_output_push(port, p);
	return;
    }
    if (port) {
	// Inbound processing, no security done but is required --
	// discard.
	checked_output_push(PORT_DISCARD, p);
	return;
    }

    // Search for existing SA (outbound only)

    const click_in6_addr *dst;
    const click_in6_addr *src;

    if (policy->action.tunnel_mode) {
	dst = &policy->action.tunnel[REMOTE];
	src = &policy->action.tunnel[LOCAL];
    } else {
	// Transport mode, SA must have addresses of the packet
	dst = &search.addr[REMOTE];
	src = &search.addr[LOCAL];
    }
    sa = lookup(*dst, *src, search, policy->sa);
    if (!sa) {
	const KMseq id = KMseq(0, ++_seq);
	sa = start_acquire(*policy, id, search, *src, *dst);
    }
    
    SET_IPSEC_SA_DATA_REFERENCE_ANNO(p, (uint64_t)sa);
    if (sa && sa->state == SA_MATURE)
	checked_output_push(sa->click_port, p);
    else
	checked_output_push(PORT_ACQUIRE, p);
}


int IPsec::attach(KeyManager &km)
{
    KM *m = new KM(km, _kmgr);
    if (!m)
	return -1;
    _kmgr = m;
    return ++_kmid;
}

bool IPsec::attach(const Element *inbound)
{
    if (_ipsec_inbound)
	return false;
    _ipsec_inbound = inbound;
    return true;
}

bool IPsec::Transform::match(const KeyInfo &info) const
{
    if (info.protocol != protocol)
	return false;

    if (info.encr.id) {
	// Encryption or combined mode algorithm required
	for (size_t a = 0; a < encr; ++a) {
	    if (alg[a].id == info.encr.id && info.encr.len >= alg[a].keylen)
		goto check_auth;
	}
	return false;
    }
 check_auth:
    if (!info.auth.id)
	return true;
    
    // Authentication algorithm required
    for (size_t a = encr; a < encr+auth; ++a) {
	if (alg[a].id == info.auth.id && info.auth.len >= alg[a].keylen)
	    return true;
    }
    return false;
}

bool IPsec::Proposal::match(const KeyInfo &info) const
{
    for (size_t i = 0; i < num_transforms; ++i)
	if (transform[i]->match(info))
	    return true;
    // No matching transform
    return false;
}

bool IPsecAddressArg::parse(const String &s, click_in6_addr &addr, const ArgContext &args)
{
    IPAddress a4;
#if HAVE_IP6
    IP6Address a6;
#endif
    if (IPAddressArg().parse(s, a4, args)) {
	memset(&addr, 0, sizeof(addr));
	addr.in6_u.u6_addr32[2] = htonl(0x0000FFFFU);
	addr.in6_u.u6_addr32[3] = a4.addr();
#if HAVE_IP6
    } else if (IP6AddressArg().parse(s, a6, args)) {
	addr = a6.in6_addr();
#endif
    } else {
	return false;
    }
    return true;
}

bool IPsecPrefixArg::parse(const String &s, click_in6_addr &addr, click_in6_addr &mask,
			   const ArgContext &args) const
{
    // Either single address or address/prefix
    IPAddress a4, m4;
#if HAVE_IP6
    IP6Address a6, m6;
#endif
    if (IPPrefixArg(allow_bare_address).parse(s, a4, m4, args)) {
	// Got address & prefix as IPv4
	memset(&addr, 0, sizeof(addr));
	memset(&mask, 0xFF, sizeof(mask));
	addr.in6_u.u6_addr32[2] = htonl(0x0000FFFFU);
	addr.in6_u.u6_addr32[3] = a4.addr();
	mask.in6_u.u6_addr32[3] = m4.addr();
#if HAVE_IP6
    } else if (IP6PrefixArg(allow_bare_address).parse(s, a6, m6, args)) {
	addr = a6.in6_addr();
	mask = m6.in6_addr();
#endif
    } else {
	// Address/prefix does not parse
	return false;
    }
    return true;
}

// The SAD and Key management support

// getspi (like PFKEYv2 GETSPI)
uint32_t IPsec::getspi(KMseq id, uint32_t low, uint32_t high)
{
    uint32_t spi = 0;
    Association *sa = lookup(id);
    if (!sa) {
	click_chatter("GETSPI: acquire SA with id(%u,%u) not found", id.km, id.seq);
	return 0;
    }

    // Note: SPI==0 is not legal value, but is always silently
    // excluded from range, so that user can simply use "getspi(id,
    // 0U, ~0U), when any SPI is ok.
    if (low)
	--low;
    if (low >= high) {
	click_chatter("GETSPI: invalid SPI range [%u-%u]", low+1, high);
	return 0;
    }

    {
	Mutex enter(_inbound_lock);

	// !!! REVISIT when lifitime is implemented: Why would 'sa'
	// !!! looked up above still exist here -- it may have
	// !!! expired

	// Wrap around, when MAX reached (skipping SPI==0)
	if (_last_spi == ~0U)
	    _last_spi = 0;

	// Use _last_spi as starting point, if it is within
	// requested range...
	if (low <= _last_spi && _last_spi < high)
	    spi = _last_spi;
	else
	    spi = low;

	uint32_t range = high - low; // Range value is starts always > 0
	do {
	    if (lookup(++spi) == NULL)
		goto got_spi;
	    if (spi == high)
		spi = low;
	} while (--range > 0);
	click_chatter("GETSPI: all SPI's in range [%u-%u] are in use", low+1, high);
	return 0;

 got_spi:
	// Update last SPI for the next call, if last_spi was used
	if (spi > _last_spi && _last_spi < high)
	    _last_spi = spi;
	// Note: src/dst for inbound reversed from outbound sa.
	Association *sainb = new Association(id, sa->policy, sa->dst, sa->src);
	sainb->spi = spi;
	// sainb->age = 0
	sainb->soft = sa->policy.action.hard;
	sainb->pfp = sa->pfp;
	add_inbound(*sainb);
    }

    // !!! Should set a default life timer which expires and kills the
    // !!! larval SA, if it is not completed by complete_getspi within
    // !!! time limit.

    // !!! TODO: Call all km's GETSPI
    return spi;
}

// A temporary helper, still want to keep Selector close to "POD", instead
// of full c++ class
static void dup_selector(IPsec::Selector &s, const IPsec::Selector &selector)
{
    if (selector.length == 0 || selector.list == NULL) {
	s.length = 0;
	s.list = NULL;
	return;
    }

    s.length = selector.length;
    s.list = new IPsec::Item[s.length];
    if (s.list == NULL) {
	s.length = 0;
	return;
    }
    memcpy((void *)s.list, (void *)selector.list, s.length * sizeof(*s.list));
}

// Usually outgoing traffic initiates negotiations. But if you
// have a server waiting for IPsec protected traffic, there will
// be no outgoing traffic until security associations are established.
//
// Trigger acquire can be used to trigger the acquire. The 'search'
// should contain the full infomation of packet belonging to such
// traffic. Does nothing if SA's are already in place.
int IPsec::trigger_acquire(KMseq id, const Match &search)
{
    PolicyItem *policy = _policy.match(search);
    if (!policy) {
	click_chatter("Acquire trigger does not match any policy");
	return -1;
    }
    // If policy does not require IPsec, then no triggering needed
    if (policy->action.proposal.num_transforms == 0)
	return 0;

    // Search for existing SA (outbound only)

    const click_in6_addr *dst;
    const click_in6_addr *src;

    if (policy->action.tunnel_mode) {
	dst = &policy->action.tunnel[REMOTE];
	src = &policy->action.tunnel[LOCAL];
    } else {
	// Transport mode, SA must have addresses of the packet
	dst = &search.addr[REMOTE];
	src = &search.addr[LOCAL];
    }
    if (lookup(*dst, *src, search, policy->sa) == NULL &&
	start_acquire(*policy, id, search, *src, *dst) == NULL)
	return -1;
    return 0;
}


// complete_acquire (like PFKEYv2 ADD)
int IPsec::complete_acquire(KMseq id, uint32_t spi,
			    const KeyInfo &key,
			    const LifeTime &soft,
			    const Selector *selector)
{
    Association *sa = lookup(id);
    if (!sa) {
	click_chatter("ADD: acquire SA with id(%u,%u) not found", id.km, id.seq);
	return -1;
    }

    Mutex enter(sa->lock);

    if (sa->state != SA_LARVAL || sa->spi != 0) {
	click_chatter("ADD: updating outbound SA not LARVAL (!= %d)", sa->state);
	return -1;
    }
    if (!sa->init_pipe(this, key)) {
	click_chatter("ADD: no matching outbound pipeline for the proposal");
	return -1;
    }
    sa->spi = spi;
    
    // -- add selector
    if (selector) {
	// !!! Should verify that the selector is subset of of the
	// !!! policy selector!
	dup_selector(sa->narrowed, *selector);
    }
    
    sa->seq = 1;
    // replay window bitmap = empty
    sa->age = LifeTime();
    sa->soft = soft;
    // TODO: constrain soft by hard life times
    // TODO: setup life timer for time based

    sa->state = SA_MATURE;
    // !!! TODO: Call all km's ADD
    return 0;
}

// complete_getspi (like PFKEYv2 UPDATE)
int IPsec::complete_getspi(KMseq id, uint32_t spi,
			   const KeyInfo &key,
			   const LifeTime &soft,
			   const Selector *selector)
{
    Association *sa = lookup(spi);
    if (!sa) {
	click_chatter("UPDATE: inbound SA SPI=%u not found", spi);
	return -1;
    }
    if (sa->kmid.km != id.km || sa->kmid.seq != id.seq) {
	click_chatter("UPDATE: inbound SA id (%u,%u) does not match with id(%u,%u)",
		      sa->kmid.km, sa->kmid.seq, id.km, id.seq);
	return -1;
    }
    if (sa->state != SA_LARVAL) {
	click_chatter("UPDATE: inbound SA SPI=%u not LARVAL (=%d)", spi, sa->state);
	return -1;
    }

    if (!sa->init_pipe(_ipsec_inbound, key)) {
	click_chatter("UPDATE: no matching inbound pipeline for the proposal");
	return -1;
    }

    // -- add selector
    if (selector) {
	// !!! Should verify that the selector is subset of of the
	// !!! policy selector!
	dup_selector(sa->narrowed, *selector);
    }

    sa->age = LifeTime();
    sa->soft = soft;
    // TODO: constrain soft by hard life times
    // TODO: setup life timer for time based

    // --------------------------------
    sa->state = SA_MATURE;

    // !!! TODO: Call all km's UPDATE
    return 0;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IPsec)
