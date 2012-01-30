#include <click/config.h>
#include "sad.hh"
#include <click/args.hh>
#include <click/packet_anno.hh>
#include <click/error.hh>

#include "elements/ipsec/sadatatuple.hh"
CLICK_DECLS

SADAnnotate::SADAnnotate()
{
}

SADAnnotate::~SADAnnotate()
{
}

static char key[KEY_SIZE+1] = "SillyPlainText";

static SADataTuple sa(key, key, 0, 0);

Packet *
SADAnnotate::simple_action(Packet *p)
{
  SET_IPSEC_SA_DATA_REFERENCE_ANNO(p, (uint64_t)&sa);
  return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(SADAnnotate)
