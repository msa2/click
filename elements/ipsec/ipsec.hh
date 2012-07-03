// -*- mode: c++; c-basic-offset: 4 -*-
#ifndef CLICK_IPSEC_HH
#define CLICK_IPSEC_HH
#include <click/element.hh>
#include <clicknet/ip6.h>

CLICK_DECLS

/*
 * =c
 * 
 * IPsec([selector,action,]...)
 * 
 * =s ipsec
 * 
 * IPsec implementation -- the RFC-4301 part
 *
 * =d
 * 
 * Element containing IPsec Security Policy Database (SPD), Security
 * Association Database (SAD) and related processing as specified by
 * RFC-4301.
 *
 * Initial fixed policy can be configured as sequence of <selector,
 * action> pairs, where selector is an instance of IPsecSelector
 * and action is an instance of IPsecPolicyAction.
 *
 * The element has two input ports. Packets to port 0 receive the
 * outbound IPsec processing, and packets to port 1 get inbound
 * policy check.
 *
 * The first 4 output ports are fixed:
 *
 * Port 0 - all outbound packets from input port 0 judged as BYPASS by
 * the policy.
 *
 * Port 1 - all inbound packets from input port 1, which pass the
 * policy check.
 *
 * Port 2 - all packets judged as DISCARD by the policy (inbound or
 * outbound)
 *
 * Port 3 - all outbound packets that require IPsec processing, but
 * for which the keys are not yet available (acquire in progress).
 *
 * The remaining ports must be attached to the IPsec transfrom elements which
 * handle the outgoing IPsec transforms.
 *
 * =e
 *
 * When creating IPsec configurations, the following generic model
 * could be used (inside and outside defined by the users
 * requirements):
 *
 *   ipsec :: IPsec(...);
 *   ipsecinbound :: IPsecInbound(ipsec);
 *
 *   // outgoing IP packets from
 *   from_inside -> [0] ipsec -> encap transforms -> to_outside
 *
 *   // incoming IP packets from
 *   from_outside -> [0] ipsecinbound -> decap transforms -> [1] ipsec [1] -> to_inside
 *
 * =a IPsecInbound
 */
class KM;
class IPsecInbound;
class IPsec : public Element {
public:
    IPsec();
    ~IPsec();
    const char *class_name() const	{ return "IPsec"; }
    const char *port_count() const	{ return "1-2/-"; }
    const char *processing() const	{ return "h/h"; }

    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *errh);

    // Some IANA constants for convenience
    enum {
	// PROTOCOL Numbers
	PROTO_RESERVED = 0,	// [RFC2407]	
	PROTO_ISAKMP = 1,	// [RFC2407]	
	PROTO_AH = 2,		// [RFC2407]	
	PROTO_ESP = 3,		// [RFC2407]	
	PROTO_IPCOMP = 4,	// [RFC2407]	
	PROTO_GIGABEAM_RADIO = 5,// [RFC4705]
    };

    /// "Well known" output ports of IPsec element
    enum {
	PORT_OUTBOUND = 0,	///< Outbound BYPASS packets 
	PORT_INBOUND = 1,	///< Inbound checked packets
	PORT_DISCARD = 2,	///< Inbound/Outbound DISCARD packets
	PORT_ACQUIRE = 3,	///< Outbound packets with ACQUIRE pending
    };

    /// Match flags are within "proto" field of the Match
    enum {
	MATCH_INBOUND = 1 << 8,		///< When set, limit selector for inbound
	MATCH_OUTBOUND = 1 << 9,	///< When set, limit selector for outbound
	MATCH_DIRECTION = (MATCH_INBOUND | MATCH_OUTBOUND),
	// -- NOTE: if both are set, selector will not match packets
	MATCH_PORTS = 1 << 10,		///< When set, the selector ports must match
	MATCH_TYPE = 1 << 11,		///< When set, the local selector port must match (MH, ICMP)
	// Indicate fields that are in low-high format (range):
	// - when set, range test: val.y <= x <= msk.y
	// - when off, mask test: (x & msk.y) == val.y
	// Note: use of mask test is faster, prefer it!
	MATCH_LPORT_RANGE = 1 << 12,	///< Local port is a range
	MATCH_RPORT_RANGE = 1 << 13,	///< Remote port is a range
	MATCH_LADDR_RANGE = 1 << 14,	///< Local address is a range
	MATCH_RADDR_RANGE = 1 << 15,	///< Remote address is a range
	MATCH_RANGE = (MATCH_LPORT_RANGE |
		       MATCH_RPORT_RANGE |
		       MATCH_LADDR_RANGE |
		       MATCH_RADDR_RANGE),
    };

    /// Meaning of port[2] and addr[2] contents in the Match
    enum {
	REMOTE = 0,
	LOCAL = 1,
    };

    // Dynamically return address or port range match mask dending on
    // REMOTE or LOCAL.
    static inline uint32_t MATCH_PORT_RANGE(int rl)
    	{ return rl == LOCAL ? MATCH_LPORT_RANGE : MATCH_RPORT_RANGE; }
    static inline  uint32_t MATCH_ADDR_RANGE(int rl)
    	{ return rl == LOCAL ? MATCH_LADDR_RANGE : MATCH_RADDR_RANGE; }

    /// SA state
    enum {
	SA_LARVAL,
	SA_MATURE,
	SA_DYING,
	SA_DEAD,
    };

    union Match {
	struct {
	    uint32_t proto;		///< Protocol (8 LSB bits only) and MATCH_bits
	    uint16_t port[2];		///< REMOTE and LOCAL port
	    click_in6_addr addr[2];	///< REMOTE/LOCAL address (128 each)
	};
	uint64_t m[5];
    };

    struct Item {
	inline bool match(const Match &search) const;
	inline bool match_port(int rl, const Match &search) const;
	inline bool match_addr(int rl, const Match &search) const;

	Match val;
	Match msk;
    };

    struct Selector {
	inline bool match(const Match &search) const;

	size_t length;		// ..the number of Items in the list.
	const Item *list;
    };

    /// The SA lifetime
    ///
    /// For the lifetime RFC-4301 (4.4.2.1) requires bytes and
    /// time, and does not seem to specify wheter time value should
    /// start from first usage of the SA or from add time. For now,
    /// implement the life time that starts counting from the point
    /// when SA changes state into MATURE.
    struct LifeTime {
	//  Possible implementations
	// - bytes
	// - packet count (xfrm)
	// - allocation count (pfkey)
	// - add time (seconds)
	// - use time (seconds)
	uint64_t bytes;
	uint64_t time;
    };

    struct Algorithm {
	uint16_t id;		///< from IANA registered value
	uint16_t keylen;	///< minimum key length in bits (or 0, if not relevant)
    };

    struct AlgInfo {
	uint16_t id;		///< Algorithm id (IANA)
	uint16_t len;		///< Length of the key data in BITS
	unsigned char *key;	///< Key data
    };

    struct KeyInfo {
	uint8_t protocol;	///< IANA IPSEC Security Protocol Identifiers
	AlgInfo encr;		///< Encryption or combined mode data
	AlgInfo auth;		///< Authentication data
    };

    /// Transform
    ///
    /// Transform describes the possibible transforms
    /// that a particular element pipeline supports.
    /// If it supports multiple algorithms, the SA
    /// configuration defines the processing.
    struct Transform {
	bool match(const KeyInfo &info) const;

	uint8_t protocol;	///< IANA IPSEC Security Protocol Identifiers
	uint8_t encr;		///< Number of encryption or combined mode algorithms
	uint8_t auth;		///< Number of integerity algorithms
	uint8_t comp;		///< Number of compression algorithms
	const Algorithm *alg;	///< Array containing encr+auth+comp entries.
    };

    /// Proposal
    ///
    /// Proposal is a set of alternative transforms, from which
    /// only one must be chosen for the security association
    struct Proposal {
	bool match(const KeyInfo &info) const;

	size_t num_transforms;
	const Transform *const* transform;
    };

    // RFC-4301 4.4.1.2 and Processing
    struct PolicyAction {
	//unsigned extseqnum:1;   // ..use 64 bit sequence numbers
	//unsigned seqoverflow:1; // ..rekey of sequence overflow
	//unsigned fragcheck:1;   // ..stateful fragment checking

	// PFP Flags
	unsigned pfp_laddr:1;	// Local address from packet
	unsigned pfp_lport:1;	// Local port from packet
	unsigned pfp_raddr:1;	// Remote address from packet
	unsigned pfp_rport:1;	// Remote port from packet
	unsigned pfp_proto:1;	// Protocol from packet

	unsigned tunnel_mode:1;	// Tunnel mode

	LifeTime hard;

	// Outer tunnel addresses if tunnel mode
	click_in6_addr tunnel[2];// REMOTE/LOCAL tunnel address
	Proposal proposal;
    };


    class PolicyItem;

    /// Key manager transaction/message identification
    struct KMseq {
	KMseq(uint32_t km, uint32_t seq) : km(km), seq(seq) {}
	uint32_t km;	///< Key manager identifier
	uint32_t seq;	///< Transaction/Message sequence number
    };

    /// TransformContext
    ///
    /// TransformContext contains the transformation specific context,
    /// as required the transform -- at least keying material, but in
    /// general any state information the transformation needs to keep
    /// around between packets. The actuall content must be defined in
    /// in a derived class specific to the transform.
    class TransformContext {
    public:
	virtual ~TransformContext() {}
	virtual void *cast(const char *) { return NULL; }
    };

    class Association {
    public:
	Association(KMseq id, const PolicyItem &policy,
		    const click_in6_addr &src,
		    const click_in6_addr &dst);
	~Association();

	inline const Proposal &proposal() const;

	bool init_pipe(const Element *e, const KeyInfo &key);
	
	const KMseq kmid;		///< Key manager idenficiation
	const PolicyItem &policy;	///< Associated policy
	const click_in6_addr src;	///< Source, but can be unspecified for outbound
	const click_in6_addr dst;	///< Destination, but can be unspecified for inbound

	volatile uint32_t lock;
	uint32_t spi;
	uint64_t seq; // TODO (no tie to the old SADatatTuple)
	// TODO: replay window bitmap
	LifeTime age;	///< Track the age/use of the SA
	LifeTime soft;	///< Soft life time expressed difference to hard life time

	// The click output port number for the IPsec transform pipe
	// line for this SA. For inbound SA, this refers to ports of
	// _ipsec_inbound (IPsecInbound) element, and for outbound SA,
	// this refers to the ports of ipsec (IPsec) itself.
	int click_port;

	uint8_t state;

	TransformContext *context;

	// pfp.val holds the data of the triggering packet and pfp.msk
	// selects the relevant fields, if any of the "Populate From
	// Packet" flags were set in PolicyAction.
	Item pfp;
	// Holds the narrowed selector, when narrowing is enabled. This
	// selector must be a subset of the original policy.selector.
	Selector narrowed;

	Association *next;
    };

    //private?
    class PolicyItem {
    public:
	PolicyItem(const Selector &selector, const PolicyAction &action)
	    : selector(selector), action(action), next(NULL), lock(0), sa(NULL)
	{}

	const Selector &selector;
	const PolicyAction &action;
	PolicyItem *next;

	// TODO IDEA: Negation list (for mini-decorrelation)
	// The complete selector is:
	// "match selector && !(match any selector before this policy item)"
	//
	// ..at policy install time, could go through the preceding policy
	// ..selectors and collect references to match items that overlap
	// ..current selector (usually this list should be short or empty)
	//
	//uint16_t nitems;
	//const Item **nlist;

	// Outbound SA's created from this policy item
	volatile uint32_t lock; // ..to protect list modifications
	Association *sa;
    };

    // Represent the collection of PolicyItem
    class Policy {
    public:
	Policy() : list(NULL), _last(&list) {}
	~Policy();

	void add(PolicyItem *item);
	PolicyItem *match(const Match &search) const;

	PolicyItem *list;
    private:
	PolicyItem **_last;
    };

    // TODO: Dynamic SPD management API
    int policy_start();
    int policy_clear();
    int policy_add(unsigned slot, const Selector &selector, const PolicyAction &action);
    int policy_commit();

    // SAD management API
    uint32_t getspi(KMseq id, uint32_t low, uint32_t high);
    int complete_getspi(KMseq id, uint32_t spi,
			const KeyInfo &key,
			const LifeTime &soft,
			const Selector *selector);
    int complete_acquire(KMseq id, uint32_t spi,
			 const KeyInfo &key,
			 const LifeTime &soft,
			 const Selector *selector);
    int trigger_acquire(KMseq id, const Match &search);

    // TODO
    int delete_sa(KMseq id, uint32_t spi,
		  const click_in6_addr *saddr, const click_in6_addr *daddr);
    // TODO
    void dump_sad(KMseq id);

    // The callback API that the Key Managers must support. The
    // naming of methods approximates the PFKEYv2 messages. The
    // ACQUIRE is the only obligatory one.
    class KeyManager {
    public:
	// getspi called -- TODO
	virtual void GETSPI(KMseq, const Association &) {}
	// complete_getspi called -- TODO
	virtual void UPDATE(KMseq, const Association &) {}
	// complete_acquire called -- TODO
	virtual void ADD(KMseq, const Association &) {}
	// TODO
	virtual void DELETE(KMseq, const Association &) {}
	// acquire processing
	virtual void ACQUIRE(KMseq, const Association &) = 0;
	// TODO (when lifetime expires)
	virtual void EXPIRE(KMseq, const Association &) {}
	// TODO (SAD cleared by request, all SA's removed)
	virtual void FLUSH(KMseq) {}
    };

    /// Lookup matching SA from a list
    Association *lookup(const click_in6_addr &dst,
			const click_in6_addr &src,
			const Match &search,
			Association *first) const;
    /// Lookup outbound SA based on KM message id
    Association *lookup(KMseq id) const;
    /// Lookup inbound SA based on unique inboud SPI
    Association *lookup(uint32_t spi) const;

    /// Lookup inbound SA based on SPI and source address
    Association *lookup(uint32_t /*spi*/, const click_in6_addr &/*src*/)
    { return NULL; }    // TODO: needed for multicast IPsec

    void push (int port, Packet *p);

    /// Register KM and return unique id > 0 (or -1 if fail)
    int attach(KeyManager &km);
    /// Register InboundIPsec element
    bool attach(const Element *inbound);
private:
    void add_inbound(Association &sa);
    Association *start_acquire(PolicyItem &policy,
			       KMseq id,
			       const Match &search,
			       const click_in6_addr &src,
			       const click_in6_addr &dst);

    const Element *_ipsec_inbound;	// The inbound IPsec front-end element
    Policy _policy;		// The current policy

    // Inbound SA database
    static const size_t _isize = 512;
    volatile uint32_t _inbound_lock;
    uint32_t _last_spi;		// Last inbound assigned spi
    Association *_inbound[_isize];// Inbound Associations

    // Known Key Managers
    KM *_kmgr;			// Registered Key Managers
    uint32_t _kmid;		// Last KM id
    uint32_t _seq;		// Last KM message seq number
};

bool IPsec::Item::match_port(int rl, const Match &search) const
{
    // rl == LOCAL or REMOTE
    const uint16_t port = search.port[rl];
    if (val.proto & MATCH_PORT_RANGE(rl))
	return val.port[rl] <= port && port <= msk.port[rl];
    return val.port[rl] == (port & msk.port[rl]);
}

bool IPsec::Item::match_addr(int rl, const Match &search) const
{
    // rl == LOCAL or REMOTE
    const click_in6_addr &addr = search.addr[rl];
    if (val.proto & MATCH_ADDR_RANGE(rl))
	return
	    memcmp(&val.addr[rl], &addr, sizeof(addr)) <= 0 &&
	    memcmp(&addr, &msk.addr[rl], sizeof(addr)) <= 0;

    return
	val.addr[rl].in6_u.u6_addr64[0] ==
	(addr.in6_u.u6_addr64[0] & msk.addr[rl].in6_u.u6_addr64[0]) &&
	val.addr[rl].in6_u.u6_addr64[1] ==
	(addr.in6_u.u6_addr64[1] & msk.addr[rl].in6_u.u6_addr64[1]);
}

bool IPsec::Item::match(const Match &search) const
{
    // Match in mask mode?
    if ((search.m[0] & msk.m[0]) == val.m[0] &&
	(search.m[1] & msk.m[1]) == val.m[1] &&
	(search.m[2] & msk.m[2]) == val.m[2] &&
	(search.m[3] & msk.m[3]) == val.m[3] &&
	(search.m[4] & msk.m[4]) == val.m[4])
	return true;
    // Any range match fields?
    if (!(val.proto & MATCH_RANGE))
	return false;
    // At least one field was a range match -- do a "slow path" and
    // match each component individually, either as a range or masked
    // compare.
    return
	((search.proto & msk.proto) == val.proto) &&
	match_port(LOCAL, search) &&
	match_port(REMOTE, search) &&
	match_addr(LOCAL, search) &&
	match_addr(REMOTE, search);
}

bool IPsec::Selector::match(const Match &search) const
{
    for (size_t i = 0; i < length; ++i)
	if (!list[i].match(search))
	    return false;
    return true;
}

const IPsec::Proposal &IPsec::Association::proposal() const
{
    return policy.action.proposal;
}


/** @class IPsecAddressArg
 * @brief Parser class for IPv4 or IPv6 addresses
 */
struct IPsecAddressArg
{
    static bool parse(const String &str, click_in6_addr &result,
		      const ArgContext &args = blank_args);
};

/** @class IPsecPrefixArg
 *  @brief Parser class for IPv4 or IPv6 address prefixes.
 */
class IPsecPrefixArg
{
public:
    IPsecPrefixArg(bool allow_bare_address_ = false)
	: allow_bare_address(allow_bare_address_)
    {
    }
    bool parse(const String &str, click_in6_addr &addr, click_in6_addr &prefix,
	       const ArgContext &args = blank_args) const;

    bool allow_bare_address;
};


CLICK_ENDDECLS
#endif
