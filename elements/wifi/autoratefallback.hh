#ifndef CLICK_AUTORATEFALLBACK_HH
#define CLICK_AUTORATEFALLBACK_HH
#include <click/element.hh>
#include <click/dequeue.hh>
#include <click/etheraddress.hh>
#include <click/bighashmap.hh>
#include <click/glue.hh>
CLICK_DECLS

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

/*
=c
AutoRateFallback([, I<KEYWORDS>])

=s Wifi

ARF wireless bit-rate selection algorithm

=d 

AutoRateFallback is based on the algorithm presented in
"WaveLAN-II: A High-Performance Wireless LAN for the 
Unliscensed Band" by Ad Kamerman and Leo Monteban
Automatically determine the txrate for a give ethernet address.

=a SetTXRate, FilterTX
*/


class AutoRateFallback : public Element { public:
  
  AutoRateFallback();
  ~AutoRateFallback();
  
  const char *class_name() const		{ return "AutoRateFallback"; }
  const char *processing() const		{ return "ah/a"; }
  const char *flow_code() const			{ return "#/#"; }
  
  int configure(Vector<String> &, ErrorHandler *);
  bool can_live_reconfigure() const		{ return true; }


  void push (int, Packet *);

  Packet *pull(int);

  void notify_noutputs(int);
  void add_handlers();
  static String static_print_stats(Element *e, void *);
  String print_rates();

  
  EtherAddress _bcast;
  struct timeval _rate_window;
  void assign_rate(Packet *);

  void process_feedback(Packet *);

  int _stepup;
  int _stepdown;
  bool _debug;
  unsigned _offset;
  unsigned _packet_size_threshold;

  struct DstInfo {
  public:
    
    EtherAddress _eth;
    Vector<int> _rates;
    
    
    int _current_index;
    int _successes;

    DstInfo() { 
    }

    DstInfo(EtherAddress eth) { 
      _eth = eth;
    }

    int rate_index(int rate) {
      int ndx = 0;
      for (int x = 0; x < _rates.size(); x++) {
	if (rate == _rates[x]) {
	  ndx = x;
	  break;
	}
      }
      return (ndx == _rates.size()) ? -1 : ndx;
    }

    int pick_rate() {
      if (_rates.size() == 0) {
	click_chatter("no rates to pick from for %s\n", 
		      _eth.s().cc());
	return 2;
      }

      if (_current_index > 0 && _current_index < _rates.size()) {
	return _rates[_current_index];
      }
      return _rates[0];
    }

    int pick_alt_rate() {
      if (_rates.size() == 0) {
	click_chatter("no rates to pick from for %s\n", 
		      _eth.s().cc());
	return 2;
      }
      return _rates[max(_current_index - 1, 0)];
    }
  };
  
  
  typedef HashMap<EtherAddress, DstInfo> NeighborTable;
  typedef NeighborTable::const_iterator NIter;

  class NeighborTable _neighbors;

  class AvailableRates *_rtable;
  bool _alt_rate;
  bool _active;
};

CLICK_ENDDECLS
#endif
