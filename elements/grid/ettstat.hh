#ifndef ETTSTATHH
#define ETTSTATHH

#include <elements/grid/linkstat.hh>
#include <elements/grid/gridgenericrt.hh>
#include <algorithm>

CLICK_DECLS

#define DBG 0

class ETTStat : public LinkStat {

protected:
  struct DelayEntry {
      unsigned delay;
      Timestamp when;
      DelayEntry(unsigned del) : delay (del), when (Timestamp::now ()) { }
    };
  struct LinkProbe {
      static const int size = 2;

      unsigned short seq_no;

      LinkProbe() : seq_no(0) { }
      LinkProbe(unsigned short s)
        : seq_no(s) { }

      // build link probe from wire format packet data
      LinkProbe(const unsigned char *);

      // write probe in wire format, return number of bytes written
      int write(unsigned char *) const;

      // update cksum of packet data whose link_probe starts at D
      static void update_cksum(unsigned char *d);
      static unsigned short calc_cksum(const unsigned char *d);
    };
public:
  ETTStat ();
  ~ETTStat ();
  const char *class_name() const { return "ETTStat"; }

  virtual int initialize(ErrorHandler*);
  virtual int configure(Vector<String>&, ErrorHandler*);
  virtual void send_hook (void);
  virtual Packet* simple_action (Packet*);
  virtual uint32_t GetPacketSize (void);
  virtual DelayEntry GetReverseDelay (const EtherAddress &eth);
  virtual DelayEntry GetForwardDelay (const EtherAddress &eth);

  inline
  static
  Timestamp GetMaxDelay ()
  {
    return Timestamp (65535 * 0.000001);
  }

protected:
  enum SampleFunctionType { EWMA = 1, MIN = 0};

  struct LinkInfo {
    EtherAddress    eth;
    probe_t lastProbe;          // most recently received first probe
    Vector<DelayEntry>  delays;    // set of calculated delays
    LinkInfo (const EtherAddress &e) : eth (e), lastProbe (Timestamp (-1), 1) { };
    LinkInfo () : lastProbe (Timestamp (-1), 1) { };
  };
  struct NodeEntry {
    Timestamp lastSeen;
    bool probesSent;
    NodeEntry () : lastSeen (Timestamp::now()), probesSent (false) { };
  };
  struct LinkEntry {
    static const int size = 8;

    struct EtherAddress eth;
    unsigned short delay;    // delay value sent to us

    LinkEntry() : delay(0) { }
    LinkEntry(const EtherAddress &e, unsigned short n) : eth(e), delay(n) { }
    LinkEntry(const unsigned char *);
    int write(unsigned char *) const;
  };
  typedef HashMap<EtherAddress, LinkInfo> ProbeMap;

  static const unsigned short ETHERTYPE_ETTPROBE = 0x7ffb;

  uint32_t m_firstSize;
  uint32_t m_secondSize;
  uint8_t m_samples;
  Timestamp m_sampleTime;
  double m_sampleMargin;
  SampleFunctionType m_functionType;
  Timestamp m_firstTime;
  Timestamp m_secondTime;
  GridGenericRouteTable* m_routeTable;

  ProbeMap m_forwardDelay;
  ProbeMap m_reverseDelay;
  HashMap<EtherAddress, NodeEntry> m_seenNodes;

  virtual void AddForwardDelayStat (EtherAddress ea, LinkProbe lp);
  virtual void AddReverseDelayStat (Packet* pkt, click_ether* eh, LinkProbe lp);

  // inlines
  inline
  void GetValidDelay (LinkInfo* linkInfo, Timestamp maxTime)
  {
    Timestamp currentTime = Timestamp::now ();
    for (DelayEntry* entry = linkInfo->delays.begin(); entry != linkInfo->delays.end(); entry++)
      {
        if ((currentTime - maxTime) > entry->when)
          {
            linkInfo->delays.erase (entry, linkInfo->delays.end ());
            break;
          }
      }
  }

  // comparator for min function
  static
  bool
  DelayCompare (DelayEntry de1, DelayEntry de2) { return de1.delay < de2.delay; }

  inline
  DelayEntry GetMinDelay (Vector<DelayEntry> delays)
  {
    DelayEntry* startIterator = delays.begin();
    DelayEntry* endIterator = delays.end();
    return std::min_element (startIterator, endIterator, ETTStat::DelayCompare)->delay;
  }
  inline
  DelayEntry GetEWMADelay (Vector<DelayEntry> delays)
  {
   return delays.at(0).delay;   // NOT implemented
  }

  inline
  unsigned GetNumberEntries (Packet* , click_ether* , LinkProbe )
   {
     return 0;
   }
  inline
  static
  unsigned GetMaxEntries (Packet* pkt, click_ether eh)
  {
    return (pkt->length() - sizeof(eh) - LinkProbe::size) / LinkEntry::size;
  }

  //region -- static checks
  bool
  IsSizeOkay (Packet* pkt)
  {
    unsigned min_sz = sizeof(click_ether) + LinkProbe::size;
    if (pkt->length() < min_sz)
    {
      pkt->kill();
      return false;
    }
    return true;
  }

  static
  bool
  IsTypeOkay (Packet* pkt, click_ether* eh)
  {
    if (ntohs(eh->ether_type) != ETHERTYPE_ETTPROBE)
      {
        pkt->kill();
        return false;
      }
    return true;
  }

  static
  bool
  IsDiscoveryProbe (click_ether* eh)
  {
    if (ntohs(eh->ether_type) == ETHERTYPE_LINKSTAT)
      {
        return true;
      }
    return false;
  }

  inline
  void
  DoDiscovery (Packet* pkt, click_ether* eh, HashMap<EtherAddress, NodeEntry>* discovered)
  {
    // record it
    NodeEntry* node = discovered->findp (EtherAddress (eh->ether_shost));
    if (node)
      {
        node->lastSeen.assign_now();
      }
    else
      {
        #if DBG
          click_chatter("%u : %s::%s : discovered node %s", (unsigned) Timestamp::now ().msecval(), "ettstat", "DoDiscovery" ,
              EtherAddress (eh->ether_shost).unparse().c_str());
        #endif
        discovered->insert (EtherAddress (eh->ether_shost),NodeEntry ());
      }

    pkt->kill();
  }

  static
  bool
  IsCheckSumOkay (Packet* pkt, click_ether*)
  {
    if (LinkProbe::calc_cksum(pkt->data() + sizeof(click_ether)) != 0) {
      pkt->kill();
      return false;
    }
    return true;
  }
  // endregion --static checks
};
CLICK_ENDDECLS
#endif
