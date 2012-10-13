/*
 * ettmetric.{cc,hh} -- estimated transmission time metric
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
 * Author: Benjamin Brewer <bb1267@my.bristol.ac.uk>
 *
 * */

#include <click/config.h>
#include <click/args.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include "elements/grid/ettmetric.hh"
#include "elements/grid/ettstat.hh"
#include "elements/grid/linkstat.hh"
CLICK_DECLS

#define DBG  0
#define DBG_MORE 0

ETTMetric::ETTMetric() :
m_etxStat (0),
m_ettStat (0),
m_packetSize (1024)
{
}

ETTMetric::~ETTMetric()
{
}

void *
ETTMetric::cast(const char *n)
{
  if (strcmp(n, "ETTMetric") == 0)
    return (ETTMetric *) this;
  else if (strcmp(n, "GridGenericMetric") == 0)
    return (GridGenericMetric *) this;
  else
    return 0;
}

// this metric combines an ETX stat and an ETTStat and can be fed its ethernet address
//      for logging purposes
int
ETTMetric::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return Args(conf, this, errh)
	.read_mp("ETXSTAT", ElementCastArg("LinkStat"), m_etxStat)
	.read_mp("ETTSTAT", ElementCastArg("ETTStatDirect"), m_ettStat)
	.read_mp("PKTSIZE", m_packetSize)
	.read("ETH", m_eth)
	.complete();
}

GridGenericMetric::metric_t
ETTMetric::get_link_metric(const EtherAddress &e, bool) const
{
  #if DBG
    click_chatter("%u : %s::%s function call for %s", (unsigned) Timestamp::now ().msecval(), name().c_str(), "get_link_metric" ,
                m_eth.unparse().c_str());
  #endif
  // get ETX
  unsigned etx = ETTMetric::GetETX (e, m_etxStat);

  // get delay and packet size for bandwidth
  unsigned delay = m_ettStat->GetReverseDelay (e).delay - 100;

  unsigned packetSize = m_ettStat->GetPacketSize ();

  // calculate with an average packet size
  double bandwidth = double(packetSize) / (double(delay)); // stay usec
  unsigned ett = etx * (unsigned) (double(m_packetSize)/bandwidth);

  // build the returned metric value
  metric_t returnMetric (ett);
  if (etx == _bad_metric.val())
    {
      returnMetric = metric_t (); // across the board punishment
    }

  #if DBG_MORE
    click_chatter("%u : %s::%s %s returning metric %u formed by delay of %u and ETX of %u for destination %s", (unsigned) Timestamp::now ().msecval(), name().c_str(),
                "get_link_metric" , m_eth.unparse().c_str(),
                ett, delay, etx, e.unparse().c_str());
  #endif


  #if DBG
    click_chatter("%u : %s::%s end function call for %s", (unsigned) Timestamp::now ().msecval(), name().c_str(), "get_link_metric" ,
                m_eth.unparse().c_str());
  #endif

  return returnMetric;
}

GridGenericMetric::metric_t
ETTMetric::append_metric(const metric_t &r, const metric_t &l) const
{
  if (!r.good() || !l.good())
    return _bad_metric;

  return metric_t(r.val() + l.val());
}

unsigned char
ETTMetric::scale_to_char(const metric_t &m) const
{
  if (!m.good() || m.val() > (0xff * 10))
    return 0xff;
  else
    return m.val() / 10;
}

GridGenericMetric::metric_t
ETTMetric::unscale_from_char(unsigned char c) const
{
  return metric_t(c * 10);
}

bool
ETTMetric::metric_val_lt(const metric_t &m1, const metric_t &m2) const
{
  return m1.val() < m2.val();
}

unsigned
ETTMetric::GetETX (const EtherAddress &ethAddress, LinkStat* etxStat)
{
    unsigned tau_fwd, tau_rev;
    unsigned r_fwd, r_rev;
    Timestamp t_fwd;

    bool res_fwd = etxStat->get_forward_rate(ethAddress, &r_fwd, &tau_fwd, &t_fwd);
    bool res_rev = etxStat->get_reverse_rate(ethAddress, &r_rev, &tau_rev);

    if (!res_fwd || !res_rev)
      return _bad_metric.val();
    if (r_fwd == 0 || r_rev == 0)
      return _bad_metric.val();

    if (r_fwd > 100)
      r_fwd = 100;
    if (r_rev > 100)
      r_rev = 100;

    unsigned val = (100 * 100 * 100) / (r_fwd * r_rev);
    assert(val >= 100);

    return val;
}

ELEMENT_PROVIDES(GridGenericMetric)
EXPORT_ELEMENT(ETTMetric)

CLICK_ENDDECLS
