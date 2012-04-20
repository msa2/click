// -*- mode: c++; c-basic-offset: 4 -*-
#ifndef CLICK_IPSECSELECTOR_HH
#define CLICK_IPSECSELECTOR_HH
#include <click/element.hh>
#include "ipsec.hh"

CLICK_DECLS

/*
 * =c
 *
 * IPsecSelector(REMOTE matcher_r1 ... matcher_rN, LOCAL matcher_l1 ..matcher_lN, DIRECTION)
 *
 * =d
 *
 * Define IPsec selector
 *
 * REMOTE lists the selector data for the remote end (in outbound
 * packets they match against destination port and address, and for
 * inbound the match is against source port and address)
 *
 * LOCAL lists the selector data for the local end (for outbound
 * packets, they match against source port and address).
 *
 * If both REMOTE and LOCAL are specified, then the given matchers
 * combine pairwise (local[0] AND remote[0], local[1] AND remote[1],
 * etc.). As indicated in RFC-4301 4.4.1.2 there is a mismatch of
 * semantics between RFC-4301 and IKEv2. Due to this, most selectors
 * should only use either LOCAL or REMOTE, and if both are used,
 * implications in combination with IKEv2 should be evaluated. Using
 * both LOCAL and REMOTE with only one matcher in each does not have
 * the problem.
 *
 * The optional keyword parameter DIRECTION can be used to limit
 * selector to match either inbound (IN) or outbound (OUT).
 *
 * The matcher syntax is:
 *
 *    high-low value:    [addrl[-addrh][#[proto:][portl[-porth]]]
 *    mask value:        [addr[&mask]][#[proto:][port[&mask]]]
 *    mask value:	 [addr[/pref]][#[proto:][port[&mask]]]
 *
 * AddressInfo name can be used in place of 'addr' or 'addr/pref'.
 *
 * =e
 *
 *    #80
 *    #udp:500
 *    #500
 *    128.1.1.0#udp:500
 *    128.1.1.1#500
 *    fe::&ff::#tcp:4000-6000
 *    address/96#icmp:1-40
 *    120.2.2.3-8#udp
 *    128.1.1.0/24
 *
 * =n
 *
 * Range and mask notations cannot be mixed in single (LOCAL/REMOTE
 * paired) matcher. Also, the protocol "proto" is independent of
 * REMOTE/LOCAL, and if specified, it must be same for both paired
 * matchers.
 */

class IPsecSelector : public Element {
public:
    IPsecSelector();
    ~IPsecSelector();

    const char *class_name() const	{ return "IPsecSelector"; }

    inline const IPsec::Selector &selector() const;

    int configure(Vector<String> &, ErrorHandler *);
private:
    IPsec::Selector _selector;
};

const IPsec::Selector &IPsecSelector::selector() const
{
    return _selector;
}
#endif
