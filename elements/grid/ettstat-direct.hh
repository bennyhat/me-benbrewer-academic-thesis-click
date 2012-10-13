#ifndef ETTSTATDIRECTHH
#define ETTSTATDIRECTHH

#include <elements/grid/ettstat.hh>

CLICK_DECLS

#define DBG  0

class ETTStatDirect : public ETTStat {

public:
  ETTStatDirect ();
  ~ETTStatDirect ();
  const char *class_name() const { return "ETTStatDirect"; }

  virtual void send_hook (void);
  virtual Packet* simple_action (Packet*);
  virtual int initialize(ErrorHandler *);

  static void StaticProbeHook(Timer *, void *e) { ((ETTStatDirect *) e)->ProbeHook(); }
  virtual void ProbeHook (void);

protected:
  virtual void DoProcessReply (Packet *p, click_ether* eh, LinkProbe lp);
  virtual void DoProcessProbe (Packet *p, click_ether* eh, LinkProbe lp);

  virtual void SendProbe (_HashMap_iterator<EtherAddress, NodeEntry> entry);
  virtual int configure(Vector<String>&, ErrorHandler*);

  static const unsigned short ETHERTYPE_ETTPROBEREPLY = 0x7ffc;

  Timestamp m_currentCutoff;

  Timer *m_probeTimer;
  uint32_t m_probeDelay;

  static
  bool
  IsProbeReply (click_ether* eh)
  {
    if (ntohs(eh->ether_type) == ETHERTYPE_ETTPROBEREPLY)
      {
        return true;
      }
    return false;
  }

  static
  bool
  IsProbe (click_ether* eh)
  {
    if (ntohs(eh->ether_type) == ETHERTYPE_ETTPROBE)
      {
        return true;
      }
    return false;
  }
};
CLICK_ENDDECLS
#endif
