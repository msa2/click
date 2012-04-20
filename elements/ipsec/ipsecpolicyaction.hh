// -*- mode: c++; c-basic-offset: 4 -*-
#ifndef CLICK_IPSECPOLICYACTION_HH
#define CLICK_IPSECPOLICYACTION_HH
#include <click/element.hh>
#include "ipsec.hh"

CLICK_DECLS

/*
 * =c
 *
 * IPsecPolicyAction(FLAGS keywords, TUNNEL addrs, BYTES life, TIME life, PROPOSAL transfroms)
 *
 * =d
 *
 * Define IPsec action on policy match
 *
 * FLAGS is a space separated keywords to set various flags for the
 * action. Current implementation defines the following keywords:
 *
 * =over 8
 *
 * =item PROTOCOL
 *
 * Set the protocol PFP flag. (PFP = "Populate From Packet")
 *
 * =item PORT
 *
 * Set the port PFP flag for the LOCAL and/or REMOTE port. Sets both
 * local and remote flags, if not limited by previous LOCAL or REMOTE
 * keyword.
 *
 * =item ADDRESS
 *
 * Set the address PFP flag for the LOCAL and/or REMOTE port. Sets
 * both local and remote flags, if not limited by previous LOCAL or
 * REMOTE keyword.
 *
 * =item LOCAL
 *
 * After this, keywords ADDRESS and PORT apply only to LOCAL. This
 * remains in effect until changed by REMOTE keyword.
 *
 * =item REMOTE
 *
 * After this, keywords ADDRESS and PORT apply only to REMOTE. This
 * remains in effect until changed by LOCAL keyword.
 *
 * =back
 *
 * TUNNEL requests the tunnel mode security association. The value is
 * two addresses separated by space. The first address is the B<remote>
 * address, which must be specified. The second address is the local
 * address, which can be left out, if someone in the packet path
 * supplies it later.
 *
 * BYTES sets the hard lifetime of the association in bytes.
 *
 * TIME sets the hard lifetime of the association in seconds.
 *
 * PROPOSAL is a space separated list of names of element instances
 * derived from the IPsecTransform element.
 */

class IPsecPolicyAction : public Element {
public:
    IPsecPolicyAction();

    const char *class_name() const	{ return "IPsecPolicyAction"; }
    
    int configure(Vector<String> &, ErrorHandler *);

    inline const IPsec::PolicyAction &action() const;

private:
    IPsec::PolicyAction _action;
};

const IPsec::PolicyAction &IPsecPolicyAction::action() const
{
    return _action;
}

#endif
