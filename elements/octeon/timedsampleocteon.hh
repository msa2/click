#ifndef CLICK_TIMEDSAMPLEOCTEON_HH
#define CLICK_TIMEDSAMPLEOCTEON_HH
#include <click/element.hh>
#include <click/timer.hh>
CLICK_DECLS

/*
=c

TimedSampleOcteon([INTERVAL)

periodically generates a packet

*/



class TimedSampleOcteon : public Element { public:

  TimedSampleOcteon();
  ~TimedSampleOcteon();

  const char *class_name() const		{ return "TimedSampleOcteon"; }
  const char *port_count() const		{ return PORTS_0_1; }
  const char *processing() const		{ return PUSH; }

  int configure(Vector<String> &, ErrorHandler *);
  int initialize(ErrorHandler *);

  void run_timer(Timer *);

 private:

    Timestamp _interval;
    int _count;
    Timer _timer;
};

CLICK_ENDDECLS
#endif
