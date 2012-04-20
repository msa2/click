// -*- c-basic-offset: 4 -*-

/*
 * ipsectransform.{cc,hh} -- IPsecTransform
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
#include <stdlib.h>
#include <click/config.h>
#include <click/args.hh>
#include <click/error.hh>
#include "ipsectransform.hh"

CLICK_DECLS

IPsecTransform::IPsecTransform()
{
    _transform = IPsec::Transform();
}

IPsecTransform::~IPsecTransform()
{
    delete[] _transform.alg;
}


int IPsecTransform::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String type;
    String encr;
    String auth;
    String comp;

    if (Args(conf, this, errh)
	.read_mp("TYPE", KeywordArg(), type)
	.read("ENCR", AnyArg(), encr)
	.read("AUTH", AnyArg(), auth)
	.read("COMP", AnyArg(), comp)
	.complete())
	return -1;

    // TODO -- database of known algorithm names, so that
    // configuration could use symbolic names instead of numbers.

    // AUTH Numbers
    //0             Reserved                        [RFC2407]	
    //1             HMAC-MD5                        [RFC2407]	
    //2             HMAC-SHA                        [RFC2407]	
    //3             DES-MAC                         [RFC2407]	
    //4             KPDK                            [RFC2407]	
    //5             HMAC-SHA2-256                   [Leech]
    //6             HMAC-SHA2-384                   [Leech]
    //7             HMAC-SHA2-512                   [Leech]
    //8             HMAC-RIPEMD                     [RFC2857]    
    //9             AES-XCBC-MAC                    [RFC3566]
    //10            SIG-RSA                         [RFC4359]
    //11            AES-128-GMAC                    [RFC4543][Errata1821]
    //12            AES-192-GMAC                    [RFC4543][Errata1821]
    //13            AES-256-GMAC                    [RFC4543][Errata1821]

    // ENCR Numbers
    //0         RESERVED                         [RFC2407]
    //1         ESP_DES_IV64                     [RFC2407]
    //2         ESP_DES                          [RFC2407]
    //3         ESP_3DES                         [RFC2407]
    //4         ESP_RC5                          [RFC2407]
    //5         ESP_IDEA                         [RFC2407]
    //6         ESP_CAST                         [RFC2407]
    //7         ESP_BLOWFISH                     [RFC2407]
    //8         ESP_3IDEA                        [RFC2407]
    //9         ESP_DES_IV32                     [RFC2407]
    //10        ESP_RC4                          [RFC2407]
    //11        ESP_NULL                         [RFC2407]
    //12        ESP_AES-CBC                      [RFC3602]
    //13        ESP_AES-CTR                      [RFC3686]
    //14        ESP_AES-CCM_8                    [RFC4309]
    //15        ESP_AES-CCM_12                   [RFC4309]
    //16        ESP_AES-CCM_16                   [RFC4309]
    //17        Unassigned                       
    //18        ESP_AES-GCM_8                    [RFC4106]
    //19        ESP_AES-GCM_12                   [RFC4106]
    //20        ESP_AES-GCM_16                   [RFC4106]
    //21        ESP_SEED_CBC                     [RFC4196]
    //22        ESP_CAMELLIA                     [RFC4312]
    //23        ESP_NULL_AUTH_AES-GMAC           [RFC4543][Errata1821]

    // COMP Numbers
    // IPCOMP_OUI        1
    // IPCOMP_DEFLATE    2        RFC 2394
    // IPCOMP_LZS        3        RFC 2395
    // IPCOMP_LZJH       4        RFC 3051


    Vector<String> list[3];
    cp_spacevec(encr, list[0]);
    cp_spacevec(auth, list[1]);
    cp_spacevec(comp, list[2]);


    const int nalgs = list[0].size() + list[1].size() + list[2].size();
    IPsec::Algorithm *alg = new IPsec::Algorithm[nalgs];
    delete[] _transform.alg;
    _transform.alg = alg;

    if (type == "ESP")
	_transform.protocol = IPsec::PROTO_ESP;
    else if (type == "AH")
	_transform.protocol = IPsec::PROTO_AH;
    else if (!IntArg().parse(type, _transform.protocol)) {
	return -1;
    }

    _transform.encr = list[0].size();
    _transform.auth = list[1].size();
    _transform.comp = list[2].size();

    const ArgContext args(this, errh);

    int slot = 0;
    for (int i = 0; i < 3; ++i) {
	for (int j = 0; j < list[i].size(); ++j) {
	    int k = list[i][j].find_left('/');
	    if (k >= 0) {
		if (!IntArg().parse(list[i][j].substring(0,k), alg[slot].id, args) ||
		    !IntArg().parse(list[i][j].substring(k+1), alg[slot].keylen, args))
		    return -1; // Error from integer parse
	    } else {
		if (!IntArg().parse(list[i][j], alg[slot].id, args))
		    return -1; // Error from integer parse
		alg[slot].keylen = 0;
	    }
	    ++slot;
	}
    }
    return 0;
}


CLICK_ENDDECLS
EXPORT_ELEMENT(IPsecTransform)
