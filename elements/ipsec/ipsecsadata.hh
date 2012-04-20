// -*- mode: c++; c-basic-offset: 4 -*-
#ifndef CLICK_IPSECSADATA_HH
#define CLICK_IPSECSADATA_HH
#include <click/element.hh>
#include "ipsec.hh"
#include "ipsecselector.hh"
CLICK_DECLS

/*
 * =c
 *
 * IPsecSAData(SPI, PROTO, ENCR, AUTH)
 *
 * Template Information element holding the IPsec SA information from
 * which the real SA instance can be constructed. This may be useful
 * in simple fixed configurations (usually in connection with IPsecKM
 * key manager).
 *
 * SPI number
 *
 * PROTO number, IPsec protocol id (like ESP, AH, ...)
 *
 * ENCR is the encryption or combined mode algorithm to use. The
 * argument is a string with two components "num hex-keystring", where
 * num is the IANA assigned algorithm number and the hex string is the
 * secret key used with this algorithm.
 *
 * AUTH is the authentication algorithm to use. The argument is a
 * string with two components "num hex-keystring", where num is the
 * IANA assigned algorithm nuymber the hex string is the secret key to
 * be used with this algorithm.
 */

class IPsecSelector;
class IPsecSAData : public Element {
public:
    IPsecSAData();
    ~IPsecSAData();

    const char *class_name() const	{ return "IPsecSAData"; }

    int configure(Vector<String> &, ErrorHandler *);

    inline const IPsec::KeyInfo &keyinfo() const;
    inline uint32_t spi() const;
private:
    IPsec::KeyInfo _key;
    uint32_t _spi;
};

inline const IPsec::KeyInfo &IPsecSAData::keyinfo() const
{
    return _key;
}

inline uint32_t IPsecSAData::spi() const
{
    return _spi;
}

#endif
