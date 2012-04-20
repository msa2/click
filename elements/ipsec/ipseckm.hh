// -*- mode: c++; c-basic-offset: 4 -*-
#ifndef CLICK_IPSECKM_HH
#define CLICK_IPSECKM_HH
#include <click/element.hh>
#include "ipsec.hh"

CLICK_DECLS
/*
 * =c
 *
 * IPsecKM(IPSEC, TRIGGER, SELECTOR, DATA,....)
 *
 * =d
 *
 * Simple IPsec Keymanager Example
 *
 * IPsecKM is a simple key manager for for IPsec module. It provides
 * preconfigured manual keys by responding to the IPsec ACQUIRE
 * requests, if the request matches any of the provided keys.
 *
 * IPSEC is mandatory and must be the IPsec element, which is
 * this key manager serves.
 *
 * TRIGGER is an optional IPsecSelector element. If specified, each
 * indivual item in selector interpreted as packet specific data and
 * used as an ACQUIRE trigger. This is a way to initiate ACQUIRE
 * processing without any actual packets.
 *
 * The remaining arguments must be pairs of
 * (IPSecSelector,IPsecSAData) elements.
 */

class IPsecSAData;
class IPsecKM : public Element, IPsec::KeyManager {
public:
    IPsecKM();
    ~IPsecKM();

    const char *class_name() const	{ return "IPsecKM"; }

    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *errh);
    void run_timer(Timer *);

    void ACQUIRE(IPsec::KMseq, const IPsec::Association &);

private:

    struct ManualKey {
	IPsecSelector *selector;
	IPsecSAData *data;
    };

    IPsec *_ipsec;		// Attached IPsec element.
    size_t _length;		// Number of (selector, key) pairs below
    ManualKey *_key;		// Array of Keys
    IPsec::KMseq _id;		// My KM identification (and seq)
    IPsecSelector *_trigger;	// Auto Acquire trigger
    Timer _timer;		// Setup if trigger exists
};

#endif
