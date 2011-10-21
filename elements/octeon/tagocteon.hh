/*
 * Copyright (c) 2011-2012 Technical Research Centre of Finland (VTT)
 *
 * Markku.Savela@vtt.fi
 */
#ifndef CLICK_TAGOCTEON_USERLEVEL_HH
#define CLICK_TAGOCTEON_USERLEVEL_HH
#include <click/element.hh>
#include <click/string.hh>
#include <click/task.hh>
CLICK_DECLS

/*
 * =c
 * TagOcteon(TYPE [, PHASE, TAG, RESTORE])
 * =s octeon
 * Execute Octeon tag switch
 *
 * =d
 *
 * Executes octeon tag switch while passing the packet from input to
 * output. The TYPE defines the new tag type, one of the following:
 * 'ORDERED', 'ATOMIC' or 'NULL'. The PHASE (0..255) defines the most
 * signicant 8 bits of the new tag, and TAG defines the lower 24
 * bits. If TAG is 0, the lower 24 bits are copied from the current
 * tag. The omitted parameters default to 0, which is equivalent of
 * TagOcteon(ORDERED,0,0).
 *
 * Unless RESTORE is set to false, the element restores the origina
 * tag state after pushing the packet to the output port.
 *
 * Includes a wait for tag switch completion.
 *
 * =a ToOcteon, FromOcteon
 *
 */
class TagOcteon : public Element { public:

  TagOcteon();
  ~TagOcteon();

  const char *class_name() const		{ return "TagOcteon"; }
  const char *port_count() const		{ return "1/1"; }
  const char *flags() const			{ return "S0"; }

  int configure(Vector<String> &, ErrorHandler *);
  void push(int port, Packet*);
  Packet *simple_action(Packet *);
  
protected:

  int _tag_type;
  uint32_t _phase;
  uint32_t _tag;
  bool _restore;
  
};


CLICK_ENDDECLS
#endif
