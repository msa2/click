// -*- mode: c++; c-basic-offset: 4 -*-
#ifndef CLICK_IPSECADAPTER_HH
#define CLICK_IPSECADAPTER_HH
#include <click/element.hh>
#include "ipsec.hh"
#include "ipsectransform.hh"

CLICK_DECLS

/*
 * =c
 *
 * IPsecAdapter
 *
 * =d
 *
 * Provide IPsec adapter for old tranform elements using the
 * SADataTuple for tranform context. For configuration details,
 * see IPsecTransform.
 *
 * =a IPsecTransform
 *
 */
class IPsecAdapter : public IPsecTransform
{
public:
    IPsec::TransformContext *setup(const IPsec::KeyInfo &key, const IPsec::Association &sa);
    Packet *simple_action(Packet *p);
};

#endif
