// -*- mode: c++; c-basic-offset: 4 -*-
#ifndef CLICK_IPSECTRANSFORM_HH
#define CLICK_IPSECTRANSFORM_HH
#include <click/element.hh>
#include "ipsec.hh"

CLICK_DECLS

/*
 * =c
 *
 * IPsecTransform(TYPE[, ENCR algs] [, AUTH algs] [, COMP algs])
 *
 * =d
 *
 * Define IPsec transformation parameters.
 *
 * TYPE is mandatory: ESP, AH, etc
 *
 * ENCR is space separated list of supported encryption or combined
 * mode algorithms (and optional minimum key length in BITS indicated
 * by "/len")
 *
 * AUTH is list of supported authentication algorithms
 *
 * COMP is list of supported IP compression algorithms
 *
 * As such this is just information element, but this can be used as a
 * base class to implement the advertised transformation.
 */

class IPsecTransform : public Element {
public:
    IPsecTransform();
    ~IPsecTransform();

    const char *class_name() const	{ return "IPsecTransform"; }
    const char *port_count() const	{ return "-/-"; }
    const char *processing() const	{ return "h/h"; }
    
    int configure(Vector<String> &, ErrorHandler *);

    inline const IPsec::Transform &transform() const;

    virtual IPsec::TransformContext *setup(const IPsec::KeyInfo &, const IPsec::Association &)
    { return NULL; }

private:
    IPsec::Transform _transform;
};

const IPsec::Transform &IPsecTransform::transform() const
{
    return _transform;
}

#endif
