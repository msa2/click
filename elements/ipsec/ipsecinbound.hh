// -*- mode: c++; c-basic-offset: 4 -*-
#ifndef CLICK_IPSECINBOUND_HH
#define CLICK_IPSECINBOUND_HH
#include <click/element.hh>

CLICK_DECLS

/*
 * =c
 * 
 * IPsecInbound(IPSEC)
 *
 * =s ipsec
 *
 * The inbound check for IPsec
 *
 * Element checks whether the packet requires inbound
 * IPsec processing (ESP, AH), and if it does, then
 * locate the security association and pass the packet
 * to the correct decapsulation pipe line.
 */

class IPsec;
class IPsecInbound : public Element {
public:
    IPsecInbound();

    const char *class_name() const	{ return "IPsecInbound"; }
    const char *port_count() const	{ return "1/-"; }
    const char *processing() const	{ return "h/h"; }

    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *errh);
    void push (int port, Packet *p);

private:
    IPsec *_ipsec;
};

CLICK_ENDDECLS
#endif

