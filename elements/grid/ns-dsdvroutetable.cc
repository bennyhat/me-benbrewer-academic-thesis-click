/*
 * ns-dsdvroutetable.{cc,hh} -- Net Sim DSDV routing element
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
 * Description: Adds a lookup route hook for NS-3 interfacing (just returns eth0) and
 *      also adds some recasts to the log call to call custom log functions
 *
 */

#include <click/config.h>
#include <stddef.h>
#include <click/args.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <click/standard/scheduleinfo.hh>
#include <click/element.hh>
#include <click/router.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include <click/packet_anno.hh>
#include <elements/grid/ns-dsdvroutetable.hh>
#include <elements/grid/linkstat.hh>
#include <elements/grid/gridgatewayinfo.hh>
#include <elements/grid/timeutils.hh>
// #include <elements/wifi/txfeedbackstats.hh>


CLICK_DECLS

#define DBG  0
#define DBG2 0
#define DBG3 0

#define FULL_DUMP_ON_TRIG_UPDATE 0

#define GRID_MAX(a, b) ((a) > (b) ? (a) : (b))
#define GRID_MIN(a, b) ((a) < (b) ? (a) : (b))

#define dsdv_assert(e) ((e) ? (void) 0 : dsdv_assert_(__FILE__, __LINE__, #e))

NetSimDSDVRouteTable::NetSimDSDVRouteTable()
{
}

NetSimDSDVRouteTable::~NetSimDSDVRouteTable()
{
    StringAccum sa;
    for (RTIter i = _rtes.begin(); i.live(); i++) {
      sa << i.value().dump() << "\n";
    }

    click_chatter ("Router %s - Final Table (Total of %u Routes)\n%s",_ip.unparse().c_str(),(unsigned) _rtes.size(),sa.c_str());
}

void *
NetSimDSDVRouteTable::cast(const char *n)
{
  if (strcmp(n, "NetSimDSDVRouteTable") == 0)
      return (NetSimDSDVRouteTable *) this;
  else if (strcmp(n, "DSDVRouteTable") == 0)
    return (DSDVRouteTable *) this;
  else if (strcmp(n, "GridGenericRouteTable") == 0)
    return (GridGenericRouteTable *) this;
  else
    return 0;
}

void
NetSimDSDVRouteTable::add_handlers()
{
  add_read_handler("nbrs_v", print_nbrs_v, 0);
  add_read_handler("nbrs", print_nbrs, 0);
  add_read_handler("rtes_v", print_rtes_v, 0);
  add_read_handler("rtes", print_rtes, 0);
  add_read_handler("ip", print_ip, 0);
  add_read_handler("eth", print_eth, 0);
  add_read_handler("seqno", print_seqno, 0);
  add_write_handler("seqno", write_seqno, 0);
#if ENABLE_PAUSE
  add_read_handler("paused", print_paused, 0, Handler::CHECKBOX);
  add_write_handler("paused", write_paused, 0);
#endif
  add_read_handler("use_old_route", print_use_old_route, 0);
  add_write_handler("use_old_route", write_use_old_route, 0);
  add_read_handler("dump", print_dump, 0);

  set_handler("lookup", Handler::OP_READ | Handler::READ_PARAM, lookup_handler);
}

int
NetSimDSDVRouteTable::lookup_handler(int , String& s, Element* e, const Handler*, ErrorHandler* errh)
{
    NetSimDSDVRouteTable *table = static_cast<NetSimDSDVRouteTable*>(e);
    IPAddress a;
    if (IPAddressArg().parse(s, a, table)) {
        int port = table->NSLookupRoute(a);
        s = String(port);
        return 0;
    } else
        return errh->error("expected IP address");
}

int
NetSimDSDVRouteTable::NSLookupRoute (const IPAddress &dest_ip)
{
  RTEntry r;
  bool res = lookup_route(dest_ip, r);

  if (res)
    {
      if (r.dest_ip != _ip)
        {
          return 1; // everything goes out port 0
        }
      else
      {
          return 0; // loop back if it's pointed at us
      }
    }
  return 1; // default, just spam out, as routing protocol will still catch it on its way out 1
}

void
NetSimDSDVRouteTable::log_dump_hook(bool reschedule)
{
  if (_log) {
    Vector<RTEntry> vec;
    get_all_entries(vec);
    reinterpret_cast<NetSimGridLogger *>(_log->cast("NetSimGridLogger"))->log_route_dump(vec, Timestamp::now());
  }
  if (reschedule)
    _log_dump_timer.schedule_after_msec(_log_dump_period);
}

void
NetSimDSDVRouteTable::get_all_entries(Vector<RTEntry> &vec)
{
#if ENABLE_PAUSE
  if (_paused) {
    for (RTIter iter = _snapshot_rtes.begin(); iter.live(); iter++) {
      const RTEntry &rte = iter.value();
#if USE_OLD_SEQ
      if (use_old_route(rte.dest_ip, _snapshot_jiffies))
        vec.push_back(_snapshot_old_rtes[rte.dest_ip]);
      else
        vec.push_back(rte);
#else
      vec.push_back(rte);
#endif
    return;
    }
  }
#endif

#if USE_OLD_SEQ
  unsigned jiff = dsdv_jiffies();
#endif
  for (RTIter iter = _rtes.begin(); iter.live(); iter++) {
    const RTEntry &rte = iter.value();
#if USE_OLD_SEQ
    if (use_old_route(rte.dest_ip, jiff))
      vec.push_back(_old_rtes[rte.dest_ip]);
    else
      vec.push_back(rte);
#else
    vec.push_back(rte);
#endif
  }
}
void
NetSimDSDVRouteTable::insert_route(const RTEntry &r, const GridGenericLogger::reason_t why)
{
  check_invariants();
  r.check();

  dsdv_assert(!_ignore_invalid_routes || r.metric.good());

  RTEntry *old_r = _rtes.findp(r.dest_ip);

  // invariant check: running timers exist for all current good
  // routes.  no timers or bogus timer entries exist for bad routes.
  // hook objects exist for each timer.
  Timer **old = _expire_timers.findp(r.dest_ip);
  HookPair **oldhp = _expire_hooks.findp(r.dest_ip);
  if (old_r && old_r->good())
    dsdv_assert(old && *old && (*old)->scheduled() && oldhp && *oldhp);
  else {
    dsdv_assert(old == 0);
    dsdv_assert(oldhp == 0);
  }

  // get rid of old expire timer
  if (old) {
    (*old)->unschedule();
    delete *old;
    delete *oldhp;
    _expire_timers.remove(r.dest_ip);
    _expire_hooks.remove(r.dest_ip);
  }

  // Note: ns dsdv only schedules a timeout for the sender of each
  // route ad, relying on the next-hop expiry logic to get all routes
  // via that next hop.  However, that won't work for general metrics,
  // so we install a timeout for *every* newly installed good route.
  if (r.good()) {
    HookPair *hp = new HookPair(this, r.dest_ip);
    Timer *t = new Timer(static_expire_hook, (void *) hp);
    t->initialize(this);
    t->schedule_after_msec(GRID_MIN(r.ttl, _timeout));

    _expire_timers.insert(r.dest_ip, t);
    _expire_hooks.insert(r.dest_ip, hp);
  }

#if USE_OLD_SEQ
  // if we are getting new seqno, save route for old seqno
  if (old_r && old_r->seq_no() < r.seq_no())
    _old_rtes.insert(r.dest_ip, *old_r);
#endif

  #if DBG
      click_chatter("%s:%s XXX inserting new route to %s as %s \n", name().c_str(), _ip.unparse().c_str(),
                    r.dest_ip.unparse().c_str(), r.dest_eth.unparse().c_str());
  #endif
  _rtes.insert(r.dest_ip, r);

  // note, we don't change any pending triggered update for this
  // updated dest.  ... but shouldn't we postpone it?  -- shouldn't
  // matter if timer fires too early, since the advertise_ok_jiffies
  // should tell us it's too early.

  if (_log)
    {
      reinterpret_cast<NetSimGridLogger *>(_log->cast("NetSimGridLogger"))->log_added_route(r, why);
    }

  check_invariants();
}

void
NetSimDSDVRouteTable::init_metric(RTEntry &r)
{
  dsdv_assert(r.num_hops() == 1);

#if SEQ_METRIC
  if (_use_seq_metric) {
    r.metric = metric_t(r.num_hops());
    Deque<unsigned> *q = _seq_history.findp(r.dest_ip);
    if (!q || q->size() < MAX_BCAST_HISTORY)
      r.metric = _bad_metric;
    else {
      dsdv_assert(q->size() == MAX_BCAST_HISTORY);
      unsigned num_missing = q->back() - (q->front() + MAX_BCAST_HISTORY - 1);
      if (num_missing > MAX_BCAST_HISTORY - OLD_BCASTS_NEEDED)
        r.metric = _bad_metric;
    }
    return;
  }
#endif

  if (_metric)
    r.metric = _metric->get_link_metric(r.dest_eth, true);
  else
    r.metric = _bad_metric;

  if (_log)
    {
        reinterpret_cast<NetSimGridLogger *>(_log->cast("NetSimGridLogger"))->LogMetricUpdate (r);
    }
}

ELEMENT_PROVIDES(DSDVRouteTable)
EXPORT_ELEMENT(NetSimDSDVRouteTable)
CLICK_ENDDECLS
