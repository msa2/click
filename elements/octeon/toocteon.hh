/*
 * Copyright (c) 2011 Technical Research Centre of Finland (VTT)
 *
 * Matias.Elo@vtt.fi
 */
#ifndef CLICK_TOOCTEON_USERLEVEL_HH
#define CLICK_TOOCTEON_USERLEVEL_HH
#include <click/element.hh>
#include <click/string.hh>
#include <click/task.hh>
CLICK_DECLS

/*
 * =c
 * ToOcteon(PORT , LOCKING)
 * =s octeon
 * Output packet to Octeon
 *
 * =d
 * Ouput content of the Click packet to the configured
 * octeon output PORT.
 *
 * The LOCKING selects the PKO locking mode (the default is
 * CMD_QUEUE). The keywords are
 *
 * =over 8
 *
 * =item ATOMIC_TAG
 *
 * Gives CVMX_PKO_LOCK_ATOMIC_TAG.
 *
 * =item CMD_QUEUE
 *
 * Gives CVMX_PKO_LOCK_CMD_QUEUE.
 *
 * =item NONE
 *
 * Gives CVMX_PKO_LOCK_NONE. Only for single thread
 * configurations, not implemented for multiple threads.
 *
 * =a FromOcteon, TagOcteon
 */

class ToOcteon : public Element { public:

  ToOcteon();
  ~ToOcteon();

  const char *class_name() const		{ return "ToOcteon"; }
  const char *port_count() const		{ return "1/0"; }
  const char *processing() const		{ return "h/h"; }

  int configure(Vector<String> &, ErrorHandler *);
  int initialize(ErrorHandler *);
  void push(int port, Packet*);
  
protected:

  unsigned long _copied, _count, _dropped;

  int _port;
  int _interface;
  int _queue;
  int _pko_locking;

  static int write_param(const String &in_s, Element *e, void *vparam, ErrorHandler *errh);
  static String read_param(Element *e, void *thunk);
};


CLICK_ENDDECLS
#endif
