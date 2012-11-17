from pox.core import core
from pox.lib.addresses import * 
from pox.lib.packet import *
from pox.lib.recoco.recoco import Timer
import re

# Get a logger
log = core.getLogger("fw")

class Firewall (object):
  def __init__(self):
    self.debug = False
    self.banned_ports = set()
    self.banned_domains = set()
    self.monitor_strings = dict()

    self.str_conn = lambda flow : "[" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]"
    self.prev_html_data = dict()
    self.timers = dict()
    self.counts_file = open('ext/counts.txt', 'w')

    with open('ext/banned-ports.txt', 'r') as f:
      for port in f:
        self.banned_ports.add(int(port.strip()))

    with open('ext/banned-domains.txt', 'r') as f:
      for domain in f:
        self.banned_domains.add(str(domain.strip()))

    with open('ext/monitored-strings.txt', 'r') as f:
      for pair in f:
        ip, string = pair.strip().split(':')
        if ip not in self.monitor_strings.keys():
          self.monitor_strings[ip] = dict()
          self.prev_html_data[ip] = dict()

        self.monitor_strings[ip][string] = 0
        self.prev_html_data[ip][string] = {True : "", False : ""}
    self.monitored_strings = dict()
    self.prev_html_data = dict()
    
    if self.debug: log.debug("Firewall initialized.")
    
  def _handle_ConnectionIn (self, event, flow, packet):
    """
    New connection event handler.
    You can alter what happens with the connection by altering the
    action property of the event.
    """
    if flow.dstport in self.banned_ports:
      if self.debug: log.debug("Denied connection " + self.str_conn(flow))
      event.action.forward = False
      event.action.deny = True
    else:
      if self.debug: log.debug("Deferred connection " + self.str_conn(flow))
      event.action.defer = True
      
  def str_conn_info(self, conn_info):
    return '%SPECIAL|'.join(sorted(list(conn_info)))
  def extract_conn_info(self, packet):
    ipv4 = packet.payload
    tcp = ipv4.payload
    dstip = str(ipv4.dstip)
    srcip = str(ipv4.srcip)
    srcport = str(tcp.srcport)
    dstport = str(tcp.dstport)
    unique_conn = (srcip, dstip, srcport, dstport)
    return unique_conn

  def external_port(self, unique_conn, reverse):
    if reverse: return unique_conn[2] # incoming
    return unique_conn[3]

  def external_ip(self, unique_conn, reverse):
    if reverse: return unique_conn[0] # incoming
    return unique_conn[1]

  def _handle_DeferredConnectionIn (self, event, flow, packet):
    """
    Deferred connection event handler.
    If the initial connection handler defers its decision, this
    handler will be called when the first actual payload data
    comes across the connection.
    """
    unique_conn = self.extract_conn_info(packet)
    sconn = self.str_conn_info(unique_conn)

    reverse = unique_conn[1] == '10.1.1.1'
    host_name_regex = re.search('Host: ([^\s]+)', packet.payload.payload.payload)
    host_name = host_name_regex.group(0)[6:] if host_name_regex else ""

    if self.debug: log.debug("Host: " + host_name)
    
    if not host_name:
      if str(flow.dst) in self.monitor_strings.keys():
        if self.debug: log.debug("Monitoring connection " + self.str_conn(flow) + " | Host: " + host_name)
        event.action.monitor_forward = True
        event.action.monitor_backward = True
        if sconn in self.timers.keys():
          assert sconn in self.monitored_strings
          self.handle_closed_connection(unique_conn, reverse, 'DJKFJD')
        
        self.monitored_strings[sconn] = {}
        self.prev_html_data[sconn] = {}
        for s in self.monitor_strings[str(flow.dst)].keys():
          self.monitored_strings[sconn][s] = 0
          self.prev_html_data[sconn][s] = {True : "", False : ""}
        self.timers[sconn] = Timer(30, self.handle_closed_connection, args=(unique_conn, reverse, 'djfsdjfksdjfksd')) # Really True?
        assert sconn in self.monitored_strings
        if self.debug: log.debug("Created Timer")
      if self.debug: log.debug("Allowed connection " + self.str_conn(flow) + " | Host: " + host_name)
      event.action.forward = True

      return # changed

    tokens = host_name.split(':')
    host_addr = tokens[0]
    host_port = tokens[1] if len(tokens) >= 2 else None
    for domain in self.banned_domains:
      if domain == host_addr:
        if self.debug: log.debug("Denied connection " + self.str_conn(flow) + " | Host: " + host_addr)
        event.action.forward = False
        event.action.deny = True
        return
      hl = len(host_addr)
      dl = len(domain)
      if hl > dl and host_addr[hl - dl : hl] == domain:
        if host_addr[hl - dl - 1] == '.':
          if self.debug: log.debug("Denied connection " + self.str_conn(flow) + " | Host: " + host_addr)
          event.action.forward = False
          event.action.deny = True
          return

    if str(flow.dst) in self.monitor_strings.keys():
      if self.debug: log.debug("Monitoring connection " + self.str_conn(flow) + " | Host: " + host_addr)
      event.action.monitor_forward = True
      event.action.monitor_backward = True
      if sconn in self.timers.keys():
        assert sconn in self.monitored_strings
        self.handle_closed_connection(unique_conn, reverse, 'dfdfd')
      
      
      self.monitored_strings[sconn] = {}
      self.prev_html_data[sconn] = {}
      for s in self.monitor_strings[str(flow.dst)].keys():
        self.monitored_strings[sconn][s] = 0
        self.prev_html_data[sconn][s] = {True : "", False : ""}
      self.timers[sconn] = Timer(30, self.handle_closed_connection, args=(unique_conn, reverse, 'dfkdjfdkj')) # really True?
      assert sconn in self.monitored_strings
      if self.debug: log.debug("Created Timer")
    if self.debug: log.debug("Allowed connection " + self.str_conn(flow) + " | Host: " + host_addr)
    event.action.forward = True
  def get_timer(self, unique_conn):
    unique_conn2 = (unique_conn[1], unique_conn[0], unique_conn[3], unique_conn[2])
    if unique_conn in self.timers.keys():
      return self.timers[unique_conn]
    if unique_conn2 in self.timers.keys():
      return self.timers[unique_conn2]
  def del_timer(self, unique_conn):
    unique_conn2 = (unique_conn[1], unique_conn[0], unique_conn[3], unique_conn[2])
    if unique_conn in self.timers.keys():
      del self.timers[unique_conn]
    if unique_conn2 in self.timers.keys():
      del self.timers[unique_conn2]

  def _handle_MonitorData (self, event, packet, reverse):
    """
    Monitoring event handler.
    Called when data passes over the connection if monitoring
    has been enabled by a prior event handler.
    """
    
    unique_conn = self.extract_conn_info(packet)
    sconn = self.str_conn_info(unique_conn)
    if self.debug: log.debug("unique_conn: " + str(unique_conn) + " " + str(self.timers.keys()) + " ")
    
    if sconn not in self.timers: # connection is over (due to 30s limit).
      return

    self.timers[sconn].cancel()
    ip_address = self.external_ip(unique_conn, reverse)
    port = self.external_port(unique_conn, reverse)
    if self.debug: log.debug("htmldata: " + str(packet.payload.payload.payload))
    for monitor_string in self.monitor_strings[ip_address].keys():
      
      data = self.prev_html_data[sconn][monitor_string][reverse] + str(packet.payload.payload.payload)
      if self.debug: log.debug("prev: " + self.prev_html_data[sconn][monitor_string][reverse])
      
      
      matched_monitor_strings = re.findall(monitor_string, data)
     
      
      self.monitored_strings[sconn][monitor_string] += len(matched_monitor_strings)
     
      if self.debug: log.debug("in Monitor: " + str(self.monitored_strings))
      
      self.prev_html_data[sconn][monitor_string][reverse] = ""
      
      rem_data = data
      while True:
        data_idx = rem_data.find(monitor_string)
        if data_idx == -1: break
        else: rem_data = rem_data[data_idx + len(monitor_string):]
     
      for i in range(min(len(monitor_string) - 1, len(rem_data)), 0, -1):

        if rem_data[len(rem_data) - i : len(rem_data)] == monitor_string[:i]:
          self.prev_html_data[sconn][monitor_string][reverse] = monitor_string[:i]
          break

      
        
      self.timers[sconn] = Timer(30, self.handle_closed_connection, args=(unique_conn, reverse, 'AFSDFD'))
      assert sconn in self.monitored_strings
      
      if self.debug: log.debug("timer created")

  def handle_closed_connection(self, unique_conn, reverse, debug):
    
    ip_address = self.external_ip(unique_conn, reverse)
    port = self.external_port(unique_conn, reverse)
    sconn = self.str_conn_info(unique_conn)
    
    if sconn not in self.monitored_strings:
      return

    count = ip_address + "," + port + "," + "%s,%s\n"

    if self.debug: log.debug("self.monitored_strings[sconn]: " + str(self.monitored_strings[sconn]))
    for monitor_string in self.monitor_strings[ip_address].keys():
      self.counts_file.write(count % (monitor_string, self.monitored_strings[sconn][monitor_string]))
      self.counts_file.flush()

    del self.monitored_strings[sconn]
    del self.prev_html_data[sconn]
    del self.timers[sconn]
    #self.del_timer(unique_conn)
    log.debug("I deleted a timer")
#test



# 3rd
# very weird keyboard. check ip address (if it is destin's)    
          
