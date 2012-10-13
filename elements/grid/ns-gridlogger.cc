/*
 * ns-gridlogger.cc
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
 * Description: Changes to a json file and xml out file format rather
 *      than the standard binary log files
 *
 */

#include <click/config.h>
#include <click/args.hh>
#include <click/glue.hh>
#include <click/error.hh>
#include "ns-gridlogger.hh"
CLICK_DECLS

NetSimGridLogger::NetSimGridLogger()
  : GridGenericLogger(), _state(WAITING), _fd(-1), _bufptr(0)
{
}

NetSimGridLogger::~NetSimGridLogger() {
  if (log_is_open())
    close_log();
}

int
NetSimGridLogger::configure(Vector<String> &conf, ErrorHandler *errh)
{
  String logfile;
  bool short_ip = true;

  int res = Args(conf, this, errh)
      .read("LOGFILE", m_eth)
      .read("SHORT_IP", short_ip)
      .complete();
  if (res < 0)
    return res;

  logfile = m_eth.unparse().c_str();

  _log_full_ip = !short_ip;
  if (logfile.length() > 0) {
    bool ok = open_log(logfile);
    if (!ok)
      return -1;
  }

  return 0;
}

void *
NetSimGridLogger::cast(const char *n)
{
  if (strcmp(n, "NetSimGridLogger") == 0)
    return (NetSimGridLogger *) this;
  else if (strcmp(n, "GridGenericLogger") == 0)
    return (GridGenericLogger *) this;
  else
    return 0;
}


void
NetSimGridLogger::add_handlers()
{
  add_read_handler("logfile", read_logfile, 0);
  add_write_handler("start_log", write_start_log, 0);
  add_write_handler("stop_log", write_stop_log, 0);
}

String
NetSimGridLogger::read_logfile(Element *e, void *)
{
  NetSimGridLogger *g = (NetSimGridLogger *) e;
  if (g->log_is_open())
    return g->_fn + "\n";

  return "\n";
}

int
NetSimGridLogger::write_start_log(const String &arg, Element *e,
			    void *, ErrorHandler *errh)
{
  NetSimGridLogger *g = (NetSimGridLogger *) e;
  if (g->log_is_open())
    g->close_log();
  bool res = g->open_log(arg);
  if (!res)
    return errh->error("unable to open logfile ``%s''", ((String) arg).c_str());
  return 0;
}

int
NetSimGridLogger::write_stop_log(const String &, Element *e,
			    void *, ErrorHandler *)
{
  NetSimGridLogger *g = (NetSimGridLogger *) e;
  if (g->log_is_open())
    g->close_log();
  return 0;
}

bool
NetSimGridLogger::open_log(const String &filename)
{
  String new_fn = filename;
  int new_fd = open(new_fn.c_str(), O_WRONLY | O_CREAT, 0777);
  if (new_fd == -1) {
    click_chatter("NetSimGridLogger %s: unable to open log file ``%s'': %s",
		  name().c_str(), new_fn.c_str(), strerror(errno));
    if (log_is_open())
      click_chatter("NetSimGridLogger %s: previous logging to ``%s'' is still enabled",
		    name().c_str(), _fn.c_str());
    return false;
  }

  if (log_is_open())
    close_log();

  _fd = new_fd;
  _fn = new_fn;

  // stream logging until I can figure out this format
  m_logStream.open((filename + ".xml").c_str());
  if (m_logStream.is_open())
    m_logStream << ("<dumps router='" + filename + "'>\n").c_str();

  // stream logging until I can figure out this format
  m_jsonStream.open((filename + ".json").c_str());
  if (m_jsonStream.is_open())
    m_jsonStream << ("["); // start a JSON array

  click_chatter("NetSimGridLogger %s: started logging to %s", name().c_str(), _fn.c_str());
  return true;
}

void
NetSimGridLogger::close_log() {
  if (_fd != -1) {
    close(_fd);
    _fd = -1;
    click_chatter("NetSimGridLogger %s: stopped logging on %s", name().c_str(), _fn.c_str());
    _fn = "";
  }
  if (m_logStream.is_open())
    {
      m_logStream << "</dumps>\n";
      m_logStream.close();
    }
  if (m_jsonStream.is_open())
    {
      m_jsonStream << ("]"); // end a JSON array
      m_jsonStream.close();
    }
}

ELEMENT_REQUIRES(ns)
ELEMENT_PROVIDES(GridGenericLogger)
EXPORT_ELEMENT(NetSimGridLogger)
CLICK_ENDDECLS
