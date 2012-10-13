/*
 * ettstat-direct.{cc,hh} -- track per-link delay, with immediate reply
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
 * Description: This is the working statistic. It gathers packet pair delay and
 *      immediately replies it to the sender
 */

#include <click/config.h>
#include <click/args.hh>
#include <clicknet/ether.h>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/timer.hh>
#include <click/straccum.hh>
#include <elements/grid/grid.hh>
#include <elements/grid/ettstat-direct.hh>
#include <elements/grid/timeutils.hh>
#include <elements/grid/dsdvroutetable.hh>
#include <ctime>
CLICK_DECLS

#define DBG  0
#define DBG_MORE 0

ETTStatDirect::ETTStatDirect () :
  m_currentCutoff (-1.0),
  m_probeDelay (1)
{
}
ETTStatDirect::~ETTStatDirect ()
{
}

int
ETTStatDirect::configure(Vector<String> &conf, ErrorHandler *errh)
{
  int res = Args(conf, this, errh)
      .read("SAMPLES", m_samples)
      .read("PERIOD", m_sampleTime)
      .read("ETH", _eth)
      .read("FIRSTSIZE", m_firstSize)
      .read("SECONDSIZE", m_secondSize)
      .read("PROBEPERIOD", m_probeDelay)
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
ETTStatDirect::initialize(ErrorHandler *)
{
  if (noutputs() > 0)
    {
      srand ((unsigned) _eth.data()); // seed with ethernet address
      _send_timer = new Timer(static_send_hook, this);
      _send_timer->initialize(this);

      m_probeTimer = new Timer(StaticProbeHook,this);
      m_probeTimer->initialize(this);

      // random time between 1 and 10 for all nodes
      Timestamp wait = Timestamp(((rand() % 100) / (double) 100) * m_sampleTime);

      #if DBG
        click_chatter("%u : stepped start set as %f",(unsigned) Timestamp::now().usecval(),wait.doubleval());
      #endif
      _send_timer->schedule_after(wait);
  }
  return 0;
}

void
ETTStatDirect::send_hook (void)
{
  #if DBG
    click_chatter("%u : %s::%s function call for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(), "send_hook" ,
                  _eth.unparse().c_str());
  #endif
  // get route table and go through entries to determine who to send to
  m_currentCutoff = (Timestamp::now () - (10 * m_sampleTime) - (m_sampleMargin*m_sampleTime));

  for (_HashMap_iterator<EtherAddress, NodeEntry> entry = m_seenNodes.begin (); entry.live(); entry++)
    {
      entry.value().probesSent = false;
    }

  for (_HashMap_iterator<EtherAddress, NodeEntry> entry = m_seenNodes.begin (); entry.live(); entry++)
    {
      if (m_currentCutoff >= entry.value().lastSeen)
        {
          #if DBG
            click_chatter("%u : %s::%s : %s timing out probes for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(), "send_hook" ,
                          _eth.unparse().c_str(), entry.key().unparse().c_str());
          #endif
          m_seenNodes.erase (entry.key());
        }
      else
        {
          // if probe hasn't been sent yet
          if (!entry.value().probesSent)
            {
              // send a probe then reschedule for a certain time from now
              SendProbe (entry);
              entry.value().probesSent = true;
              m_probeTimer->schedule_after_msec (m_probeDelay);
              break;
            }
        }
    }
  // random jitter around the probe period for reschedule
  srand ((unsigned) _eth.data() + (unsigned) Timestamp::now().msecval());
  unsigned max_jitter = m_sampleTime.msecval() / 10;
  unsigned j = rand() % (max_jitter * 2);

  _send_timer->reschedule_after_msec(m_sampleTime.msecval() + j - max_jitter);

  #if DBG
    click_chatter("%u : %s::%s end function call for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(), "send_hook" ,
                _eth.unparse().c_str());
  #endif
}

// this is the async function for going through neighbors
void
ETTStatDirect::ProbeHook (void)
{
  for (_HashMap_iterator<EtherAddress, NodeEntry> entry = m_seenNodes.begin (); entry.live(); entry++)
    {
      if (m_currentCutoff >= entry.value().lastSeen)
        {
          #if DBG
            click_chatter("%u : %s::%s : %s timing out probes for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(), "send_hook" ,
                          _eth.unparse().c_str(), entry.key().unparse().c_str());
          #endif
          m_seenNodes.erase (entry.key());
        }
      else
        {
          // if probe hasn't been sent yet
          if (!entry.value().probesSent)
            {
              // send a probe then reschedule for a certain time from now
              SendProbe (entry);
              entry.value().probesSent = true;
              m_probeTimer->schedule_after_msec (m_probeDelay);
              return;
            }
        }
    }
}

void
ETTStatDirect::SendProbe (_HashMap_iterator<EtherAddress, NodeEntry> entry)
{
  #if DBG_MORE
    click_chatter("%u : %s::%s : %s function sending probes to %s", (unsigned) Timestamp::now ().usecval(), name().c_str(),
                "send_hook" , _eth.unparse().c_str(), entry.key().unparse().c_str());
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
  LinkProbe::update_cksum (firstPacket->data() + sizeof(click_ether));

  // build second packet
  LinkProbe secondProbe (2);
  unsigned char *secondProbeData = secondPacket->data() + sizeof(click_ether);
  secondProbeData += secondProbe.write(secondProbeData);
  LinkProbe::update_cksum (secondPacket->data() + sizeof(click_ether));

  // send them out
  checked_output_push(0, firstPacket);
  checked_output_push(0, secondPacket);
}

// called on packet receive
Packet *
ETTStatDirect::simple_action(Packet *p)
{
  #if DBG
    click_chatter("%u : %s::%s function call for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(), "simple_action" ,
                  _eth.unparse().c_str());
  #endif
  click_ether *eh = (click_ether *) p->data();
  LinkProbe lp(p->data() + sizeof(click_ether));

  if (ETTStat::IsDiscoveryProbe(eh))
    {
      DoDiscovery (p, eh, &m_seenNodes);
      return 0;
    }

  if (ETTStatDirect::IsProbeReply(eh))
    {
      DoProcessReply (p, eh, lp);
    }

  if (ETTStatDirect::IsProbe(eh))
    {
      DoProcessProbe (p, eh, lp);
    }

  #if DBG
    click_chatter("%u : %s::%s end function call for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(), "simple_action" ,
                _eth.unparse().c_str());
  #endif
  return 0;
}

void
ETTStatDirect::DoProcessReply (Packet *p, click_ether* eh, LinkProbe lp)
{
  #if DBG
    click_chatter("%u : %s::%s function call for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(), "DoProcessReply" ,
                  _eth.unparse().c_str());
  #endif
  // set reverse sample
  AddReverseDelayStat (p, eh, lp);
  #if DBG
    click_chatter("%u : %s::%s end function call for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(), "DoProcessReply" ,
                _eth.unparse().c_str());
  #endif
}

void
ETTStatDirect::DoProcessProbe (Packet *p, click_ether* eh, LinkProbe lp)
{
  if (!ETTStat::IsTypeOkay (p, eh))
    {
      return;
    }

  #if DBG
    click_chatter("%u : %s::%s function call for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(), "DoProcessProbe" ,
                _eth.unparse().c_str());
  #endif

  // set forward sample
  AddForwardDelayStat (EtherAddress(eh->ether_shost), lp);

  // get a forward delay
  DelayEntry delay = GetForwardDelay (EtherAddress(eh->ether_shost));

  // if we have one to send
  if (delay.delay != (unsigned) ETTStat::GetMaxDelay().usecval())
    {
      LinkInfo* stupid = m_forwardDelay.findp(EtherAddress(eh->ether_shost));
      stupid->delays.pop_front();

      #if DBG_MORE
        click_chatter("%u : %s::%s : %s function sending delay %u to %s", (unsigned) Timestamp::now ().usecval(), name().c_str(),
                    "send_hook" , _eth.unparse().c_str(),
                    delay.delay, EtherAddress(eh->ether_shost).unparse().c_str());
      #endif

      // build it and send it, that's it
      WritablePacket *replyPacket = Packet::make(42 + 2);
      ASSERT_4ALIGNED(replyPacket->data());
      replyPacket->pull(2);
      memset(replyPacket->data(), 0, replyPacket->length());
      replyPacket->set_timestamp_anno(Timestamp::now());

      // fill in ethernet headers
      click_ether *replyEthHeader = (click_ether *) replyPacket->data();
      memcpy(replyEthHeader->ether_dhost, eh->ether_shost, 6);
      replyEthHeader->ether_type = htons(ETHERTYPE_ETTPROBEREPLY);
      memcpy(replyEthHeader->ether_shost, _eth.data(), 6);

      // build first packet
      LinkProbe replyProbe(1);
      unsigned char *firstProbeData = replyPacket->data() + sizeof(click_ether);
      firstProbeData += replyProbe.write(firstProbeData);
      LinkProbe::update_cksum (replyPacket->data() + sizeof(click_ether));

      LinkEntry linkEntry (EtherAddress(eh->ether_shost), delay.delay);
      firstProbeData += linkEntry.write(firstProbeData);

      checked_output_push(0, replyPacket);
    }

  p->kill();
  #if DBG
    click_chatter("%u : %s::%s end function call for %s", (unsigned) Timestamp::now ().usecval(), name().c_str(), "DoProcessProbe" ,
                _eth.unparse().c_str());
  #endif
}

EXPORT_ELEMENT(ETTStatDirect)
CLICK_ENDDECLS
