// -*- c-basic-offset: 4 -*-

/*
 * ipsecsadata.{cc,hh} -- IPsecSAData
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
#include "ipsecselector.hh"
#include "ipsecsadata.hh"

CLICK_DECLS

IPsecSAData::IPsecSAData() : _key(IPsec::KeyInfo())
{
}

IPsecSAData::~IPsecSAData()
{
    delete[] _key.encr.key;
    delete[] _key.auth.key;
}


class AlgInfoArg
{
public:
    bool parse(const String &str, IPsec::AlgInfo &result, const ArgContext &args = blank_args);
};

bool AlgInfoArg::parse(const String &str, IPsec::AlgInfo &info, const ArgContext &args)
{
    Vector<String> conf;
    String key;
    cp_spacevec(str, conf);

    // !!! The keywords ID and DATA are dummies. Perhaps should just
    // !!! use IntArg() and StringArg() parse functions directly for
    // !!! conf[0] and conf[1]?
    if (Args(conf, args.context(), args.errh())
	.read_mp("ID", info.id)
	.read_mp("DATA", key)
	.complete() < 0)
	return false;

    info.key = new unsigned char[key.length()];
    if (!info.key)
	return false;
    info.len = 8 * key.length();
    memcpy(info.key, key.data(), key.length());
    return true;
}

int IPsecSAData::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String encr;
    String auth;

    delete[] _key.encr.key;
    delete[] _key.auth.key;

    _key = IPsec::KeyInfo();

    if (Args(conf, this, errh)
	.read("SPI", IntArg(), _spi)
	.read("PROTO", IntArg(), _key.protocol)
	.read("ENCR", AlgInfoArg(), _key.encr)
	.read("AUTH", AlgInfoArg(), _key.auth)
	.complete() < 0)
	return -1;
    return 0;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IPsecSAData)
