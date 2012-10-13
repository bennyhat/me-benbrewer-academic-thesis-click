/*
 * ettstat.{cc,hh} -- track per-link delay
 *
 * Copyright (c) 2012 Benjamin Brewer
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
 *
 * Author: Benjamin Brewer
 *
 * Description: This is a version of the linkstat that sends replies in the next
 *      probes. Pretty sure it's broken. Don't use, here for example only.
 */

#include <click/config.h>
#include <click/args.hh>
#include <clicknet/ether.h>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/timer.hh>
#include <click/straccum.hh>
#include <elements/grid/grid.hh>
#include <elements/grid/ettstat.hh>
#include <elements/grid/timeutils.hh>
#include <elements/grid/dsdvroutetable.hh>
#include <ctime>
CLICK_DECLS

#define DBG  0
#define DBG_MORE 0

ETTStat::ETTStat () :
  m_firstSize (30),
  m_secondSize (30),
  m_samples (10),
  m_sampleTime (1.0),
  m_sampleMargin (0.1),
  m_firstTime (-1.0),
  m_secondTime (-1.0),
  m_forwardDelay (),
  m_reverseDelay ()
{
  m_functionType = MIN;
}
ETTStat::~ETTStat ()
{
}

int
ETTStat::configure(Vector<String> &conf, ErrorHandler *errh)
{
  int res = Args(conf, this, errh)
      .read("SAMPLES", m_samples)
      .read("PERIOD", m_sampleTime)
      .read("ETH", _eth)
      .read("FIRSTSIZE", m_firstSize)
      .read("SECONDSIZE", m_secondSize)
      .complete();
  if (res < 0)
    return res;

  unsigned min_sz = sizeof(click_ether) + LinkProbe::size;
  if (m_firstSize < min_sz)
    return errh->error("Specified packet size is less than the minimum probe size of %u", min_sz);

  if (m_samples <= 0)
    return errh->error ("Cannot have a 0 or negative sample size %u", m_samples);

  if (m_functionType != 0 && m_functionType != 1)
    return errh->error ("Sample function type must be either 0 (MIN) or 1 (EWMA)");

  if (!_eth)
    return errh->error("Source Ethernet address must be specified to send probes");

  return res;
}

int
ETTStat::initialize(ErrorHandler *)
{
  if (noutputs() > 0)
    {
      srand ((unsigned) _eth.data()); // seed with ethernet address
      _send_timer = new Timer(static_send_hook, this);
      _send_timer->initialize(this);
      // 4 seconds for ETX to do discovery
      Timestamp wait = Timestamp (4 + ((_eth.sdata()[2] / 256) * (0.001) * m_sampleTime.doubleval()));
      #if DBG
        click_chatter("%u : stepped start set as %u",(unsigned) Timestamp::now().usecval(),(unsigned) wait.usecval());
      #endif
      _send_timer->schedule_after(wait);
  }
  return 0;
}

void
ETTStat::send_hook (void)
{
  #if DBG
    click_chatter("%u : %s::%s function call for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(), "send_hook" ,
                  _eth.unparse().c_str());
  #endif
  // get route table and go through entries to determine who to send to
  Timestamp tmpCutoff = (Timestamp::now () - (m_samples * m_sampleTime) - (m_sampleMargin*m_sampleTime));

  for (_HashMap_iterator<EtherAddress, NodeEntry> entry = m_seenNodes.begin (); entry.live(); entry++)
    {
      if (tmpCutoff >= entry.value().lastSeen)
        {
          #if DBG
            click_chatter("%u : %s::%s : %s timing out probes for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(), "send_hook" ,
                          _eth.unparse().c_str(), entry.key().unparse().c_str());
          #endif
          m_seenNodes.erase (entry.key());
        }
      else
        {
          // get their metric from reverse
          DelayEntry delay = GetForwardDelay (entry.key());

          #if DBG_MORE
            click_chatter("%u : %s::%s : %s function sending delay %u to %s", (unsigned) Timestamp::now ().usecval(), name().c_str(),
                        "send_hook" , _eth.unparse().c_str(),
                        delay.delay, entry.key().unparse().c_str());
          #endif

          // send them two probes with the metric entry in each
          WritablePacket *firstPacket = Packet::make(m_firstSize + 2); // +2 for alignment
          if (firstPacket == 0)
            {
              #if DBG_MORE
                click_chatter("%u : %s::%s : %s failed to make first probe for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(), "send_hook" ,
                              _eth.unparse().c_str(), entry.key().unparse().c_str());
              #endif
              return;
            }

          WritablePacket *secondPacket = Packet::make(m_secondSize + 2); // +2 for alignment
          if (secondPacket == 0)
            {
              #if DBG_MORE
                click_chatter("%u : %s::%s : %s failed to make second probe for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(), "send_hook" ,
                              _eth.unparse().c_str(), entry.key().unparse().c_str());
              #endif
              return;
            }

          ASSERT_4ALIGNED(firstPacket->data());
          ASSERT_4ALIGNED(secondPacket->data());
          firstPacket->pull(2);
          secondPacket->pull(2);
          memset(firstPacket->data(), 0, firstPacket->length());
          memset(secondPacket->data(), 0, secondPacket->length());

          firstPacket->set_timestamp_anno(Timestamp::now());
          secondPacket->set_timestamp_anno(Timestamp::now());

          // fill in ethernet headers
          click_ether *firstEthHeader = (click_ether *) firstPacket->data();
          click_ether *secondEthHeader = (click_ether *) secondPacket->data();
          memcpy(firstEthHeader->ether_dhost, entry.key().data(), 6); // unicast
          memcpy(secondEthHeader->ether_dhost, entry.key().data(), 6); // unicast
          firstEthHeader->ether_type = htons(ETHERTYPE_ETTPROBE);
          secondEthHeader->ether_type = htons(ETHERTYPE_ETTPROBE);
          memcpy(firstEthHeader->ether_shost, _eth.data(), 6);
          memcpy(secondEthHeader->ether_shost, _eth.data(), 6);

          // build first packet
          LinkProbe firstProbe(1);
          unsigned char *firstProbeData = firstPacket->data() + sizeof(click_ether);
          firstProbeData += firstProbe.write(firstProbeData);
          LinkEntry firstLinkEntry (entry.key(), delay.delay);
          firstProbeData += firstLinkEntry.write(firstProbeData);
          LinkProbe::update_cksum (firstPacket->data() + sizeof(click_ether));

          // build second packet
          LinkProbe secondProbe (2);
          unsigned char *secondProbeData = secondPacket->data() + sizeof(click_ether);
          secondProbeData += secondProbe.write(secondProbeData);
          LinkEntry secondLinkEntry (entry.key(), delay.delay);
          secondProbeData += secondLinkEntry.write(secondProbeData);
          LinkProbe::update_cksum (secondPacket->data() + sizeof(click_ether));

          // send them out
          checked_output_push(0, firstPacket);
          checked_output_push(0, secondPacket);
        }
    }
  //unsigned max_jitter = _period / 10;
  //unsigned j = click_random(0, max_jitter * 2);
  _send_timer->reschedule_after_msec(m_sampleTime.msecval());

  #if DBG
    click_chatter("%u : %s::%s end function call for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(), "send_hook" ,
                _eth.unparse().c_str());
  #endif
}

Packet *
ETTStat::simple_action(Packet *p)
{
  click_ether *eh = (click_ether *) p->data();
  LinkProbe lp(p->data() + sizeof(click_ether));

  if (ETTStat::IsDiscoveryProbe(eh))
    {
      DoDiscovery (p, eh, &m_seenNodes);
      return 0;
    }

  if (!IsSizeOkay (p))
    {
      return 0;
    }
  if (!ETTStat::IsTypeOkay (p, eh))
    {
      return 0;
    }

  #if DBG
    click_chatter("%u : %s::%s function call for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(), "simple_action" ,
                _eth.unparse().c_str());
  #endif

  // set forward sample
  AddForwardDelayStat (EtherAddress(eh->ether_shost), lp);

  // set reverse sample
  AddReverseDelayStat (p, eh, lp);

  p->kill();

  #if DBG
    click_chatter("%u : %s::%s end function call for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(), "simple_action" ,
                _eth.unparse().c_str());
  #endif
  return 0;
}

void
ETTStat::AddForwardDelayStat (EtherAddress ea, LinkProbe lp)
{
  #if DBG
    click_chatter("%u : %s::%s function call for %s and sequence %u", (unsigned) Timestamp::now ().usecval(), name().c_str(), "AddForwardDelayStat" ,
                  _eth.unparse().c_str(),lp.seq_no );
  #endif
  LinkInfo* linkInfo = m_forwardDelay.findp (ea);

  if (!linkInfo)
    {
      m_forwardDelay.insert (ea, LinkInfo (ea));
      linkInfo =  m_forwardDelay.findp (ea);
    }

    //// these are unicast and therefore no need to worry about sequencing
    // if packet is of type for packet 1 and packet 1 mark is not set
  if (lp.seq_no == 1)
    {
      linkInfo->lastProbe.when = Timestamp::now (); // mark packet 1 time
      #if DBG
        click_chatter("%u : %s::%s end function call for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(),
                    "AddForwardDelayStat" , _eth.unparse().c_str());
      #endif
      return;  // return
    }
  // else if packet is of type for packet 2 and packet 1 mark is set
  else if (lp.seq_no == 2 && !linkInfo->lastProbe.when.is_negative())
    {
      // calculate difference between packet 1 and packet 2 mark
      Timestamp difference = Timestamp::now() - linkInfo->lastProbe.when;

      if (difference.usecval() < ETTStat::GetMaxDelay().usecval())
        {
          #if DBG_MORE
            click_chatter("%u : %s::%s %s storing delay for %s of %u", (unsigned) Timestamp::now ().usecval(), name().c_str(),
                        "AddForwardDelayStat" , _eth.unparse().c_str(), ea.unparse().c_str(), (unsigned) difference.usecval());
          #endif
          linkInfo->delays.clear ();
          linkInfo->delays.push_front (DelayEntry (difference.usecval()));
        }
      else
        {
          #if DBG_MORE
            click_chatter("%u : %s::%s %s storing delay for %s of %u", (unsigned) Timestamp::now ().usecval(), name().c_str(),
                        "AddForwardDelayStat" , _eth.unparse().c_str(), ea.unparse().c_str(), ETTStat::GetMaxDelay());
          #endif
        }

      linkInfo->lastProbe.when = Timestamp (-1.0); // mark packet 1 time as 0
    }
  // 2 and then another 2, just reset
  else
    {
      linkInfo->lastProbe.when = Timestamp (-1.0); // mark packet 1 time as 0
    }
  #if DBG
    click_chatter("%u : %s::%s real end function call for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(),
                "AddForwardDelayStat" , _eth.unparse().c_str());
  #endif
}

void
ETTStat::AddReverseDelayStat (Packet* pkt, click_ether* eh, LinkProbe )
{
  #if DBG
    click_chatter("%u : %s::%s function call for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(), "AddReverseDelayStat" ,
                _eth.unparse().c_str());
  #endif
  // look in received packet for info about our outgoing link
  EtherAddress ea = EtherAddress(eh->ether_shost);

  const unsigned char *d = pkt->data() + sizeof(click_ether) + LinkProbe::size;
  //for (unsigned i = 0; i < entries; i++, d += LinkEntry::size)
    //{
      LinkEntry linkEntry(d);
      if (linkEntry.eth == _eth)
        {
          LinkInfo* linkInfo = m_reverseDelay.findp (ea);
          if (!linkInfo)
            {
              m_reverseDelay.insert (ea, LinkInfo (ea));
              linkInfo =  m_reverseDelay.findp (ea);
            }
          #if DBG_MORE
            click_chatter("%u : %s::%s %s storing delay for %s of %u", (unsigned) Timestamp::now ().usecval(), name().c_str(),
                      "AddReverseDelayStat" , _eth.unparse().c_str(), ea.unparse().c_str(), linkEntry.delay);
          #endif
          linkInfo->delays.push_front(DelayEntry (linkEntry.delay));
        }
    //}
  #if DBG
    click_chatter("%u : %s::%s end function call for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(),
                "AddReverseDelayStat" , _eth.unparse().c_str());
  #endif
}

ETTStat::DelayEntry
ETTStat::GetReverseDelay (const EtherAddress &eth)
{
  #if DBG
    click_chatter("%u : %s::%s function call for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(), "GetReverseDelay" ,
                  _eth.unparse().c_str());
  #endif
  LinkInfo* linkInfo =  m_reverseDelay.findp (eth);

  if (!linkInfo)
    {
      m_reverseDelay.insert (eth, LinkInfo (eth));
      linkInfo =  m_reverseDelay.findp (eth);
    }

  GetValidDelay (linkInfo, (m_samples * m_sampleTime) + (2 * m_sampleMargin * m_sampleTime));

  #if DBG
    click_chatter("%u : %s::%s end function call for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(),
                "GetReverseDelay" , _eth.unparse().c_str());
  #endif

  if (linkInfo->delays.empty())
    {
      return DelayEntry ((unsigned) ETTStat::GetMaxDelay().usecval());
    }
  if (m_functionType == MIN)
    return GetMinDelay (linkInfo->delays);
  else if (m_functionType == EWMA)
    return GetEWMADelay (linkInfo->delays);
  else
    return DelayEntry ((unsigned) ETTStat::GetMaxDelay().usecval());
}

ETTStat::DelayEntry
ETTStat::GetForwardDelay (const EtherAddress &eth)
{
  #if DBG
    click_chatter("%d : %s::%s function call for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(), "GetForwardDelay",  _eth.unparse().c_str());
  #endif

  LinkInfo* linkInfo =  m_forwardDelay.findp (eth);

  if (!linkInfo)
    {
      m_forwardDelay.insert (eth, LinkInfo (eth));
      linkInfo =  m_forwardDelay.findp (eth);
    }

  GetValidDelay (linkInfo, m_sampleTime + (m_sampleMargin * m_sampleTime));

  #if DBG
    click_chatter("%u : %s::%s end function call for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(),
                "GetForwardDelay" , _eth.unparse().c_str());
  #endif

  if (linkInfo->delays.empty())
    {
      return DelayEntry ((unsigned) ETTStat::GetMaxDelay().usecval());
    }
  else
    return linkInfo->delays.front();
}

uint32_t
ETTStat::GetPacketSize (void)
{
  return m_secondSize;
}

int
ETTStat::LinkEntry::write(unsigned char *d) const
{
  memcpy(d, eth.data(), 6);
  LinkStat::write_ushort_at(d + 6, delay);
  return size;
}

ETTStat::LinkEntry::LinkEntry (const unsigned char *d)
  : eth(d), delay (ushort_at(d + 6))
{
}
ETTStat::LinkProbe::LinkProbe(const unsigned char *d)
  : seq_no(ushort_at(d + 0))
{
}

int
ETTStat::LinkProbe::write(unsigned char *d) const
{
  //click_chatter ("in write");
  write_ushort_at(d + 0, seq_no);
  return size;
}

void
ETTStat::LinkProbe::update_cksum(unsigned char *)
{

}

unsigned short
ETTStat::LinkProbe::calc_cksum(const unsigned char *)
{
  return 0;
}

EXPORT_ELEMENT(ETTStat)
CLICK_ENDDECLS
