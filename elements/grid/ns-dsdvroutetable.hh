#ifndef CLICK_NS_DSDVROUTETABLE_HH
#define CLICK_NS_DSDVROUTETABLE_HH

#include <elements/grid/dsdvroutetable.hh>
#include <elements/grid/ns-gridlogger.hh>
CLICK_DECLS

class NetSimDSDVRouteTable : public DSDVRouteTable {

public:
  NetSimDSDVRouteTable();
  virtual ~NetSimDSDVRouteTable();

  const char *class_name() const { return "NetSimDSDVRouteTable"; }
  void *cast (const char *);

  virtual void add_handlers();

protected:
  virtual int NSLookupRoute (const IPAddress &dest_ip);
  static int lookup_handler (int, String& s, Element* e, const Handler*, ErrorHandler* errh);
  virtual void log_dump_hook(bool reschedule);
  virtual void get_all_entries(Vector<RTEntry> &vec);
  virtual void insert_route(const RTEntry &, const GridGenericLogger::reason_t why);
  virtual void init_metric (RTEntry &r);
};
CLICK_ENDDECLS
#endif
