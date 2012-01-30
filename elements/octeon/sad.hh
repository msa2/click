// -*- mode: c++; c-basic-offset: 4 -*-

#ifndef CLICK_SAD_USERLEVEL_HH
#define CLICK_SAD_USERLEVEL_HH
#include <click/element.hh>
CLICK_DECLS

/*
 * =c
 * SadAnnotate
 */

class SADAnnotate : public Element { public:

    SADAnnotate();
    ~SADAnnotate();

    const char *class_name() const	{ return "SADAnnotate"; }
    const char *port_count() const	{ return "1/1"; }
    const char *processing() const	{ return "h/h"; }

    Packet *simple_action(Packet *);

private:
};

CLICK_ENDDECLS
#endif
