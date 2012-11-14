from pox.core import core
from pox.lib.addresses import * 
from pox.lib.packet import *
from pox.lib.recoco.recoco import Timer
import re

# Get a logger
log = core.getLogger("fw")

class Firewall (object):
  def __init__(self):
    self.debug = True
    self.banned_ports = set()
    self.banned_domains = set()
    self.monitor_strings = dict()

    self.str_conn = lambda flow : "[" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]"
    self.prev_html_data = dict()
    self.timers = dict()
    self.counts_file = open('/root/pox/ext/counts.txt', 'w')

    with open('/root/pox/ext/banned-ports.txt', 'r') as f:
      for port in f:
        self.banned_ports.add(int(port.strip()))

    with open('/root/pox/ext/banned-domains.txt', 'r') as f:
      for domain in f:
        self.banned_domains.add(str(domain.strip()))

    with open('/root/pox/ext/monitored-strings.txt', 'r') as f:
      for pair in f:
        ip, string = pair.strip().split(':')
        if ip not in self.monitor_strings.keys():
          self.monitor_strings[ip] = dict()
          self.prev_html_data[ip] = dict()

        self.monitor_strings[ip][string] = 0
        self.prev_html_data[ip][string] = ""
   
    
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
    else:
      if self.debug: log.debug("Deferred connection " + self.str_conn(flow))
      event.action.defer = True
      

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
    
    host_name_regex = re.search('Host: ([^\s]+)', packet.payload.payload.payload)
    host_name = host_name_regex.group(0)[6:] if host_name_regex else ""

    if self.debug: log.debug("Host: " + host_name)

    if not host_name:
      if str(flow.dst) in self.monitor_strings.keys():
        if self.debug: log.debug("Monitoring connection " + self.str_conn(flow) + " | Host: " + host_name)
        event.action.monitor_forward = True
        event.action.monitor_backward = True
        if unique_conn in self.timers.keys(): # this will never happen.
          self.timers[unique_conn].cancel()
        self.timers[unique_conn] = Timer(30, self.handle_closed_connection, args=(unique_conn, True)) # Really True?
        if self.debug: log.debug("Created Timer")
      if self.debug: log.debug("Allowed connection " + self.str_conn(flow) + " | Host: " + host_name)
      event.action.forward = True
      return # changed
    
    for domain in self.banned_domains:
      if domain == host_name:
        if self.debug: log.debug("Denied connection " + self.str_conn(flow) + " | Host: " + host_name)
        event.action.forward = False
        return
      hl = len(host_name)
      dl = len(domain)
      if hl > dl and host_name[hl - dl : hl] == domain:
        if host_name[hl - dl - 1] == '.':
          if self.debug: log.debug("Denied connection " + self.str_conn(flow) + " | Host: " + host_name)
          event.action.forward = False
          return

    if str(flow.dst) in self.monitor_strings.keys():
      if self.debug: log.debug("Monitoring connection " + self.str_conn(flow) + " | Host: " + host_name)
      event.action.monitor_forward = True
      event.action.monitor_backward = True
      if unique_conn in self.timers.keys(): # this will never happen.
        self.timers[unique_conn].cancel()
      self.timers[unique_conn] = Timer(30, self.handle_closed_connection, args=(unique_conn, True)) # really True?
      if self.debug: log.debug("Created Timer")
    if self.debug: log.debug("Allowed connection " + self.str_conn(flow) + " | Host: " + host_name)
    event.action.forward = True
    
  def _handle_MonitorData (self, event, packet, reverse):
    """
    Monitoring event handler.
    Called when data passes over the connection if monitoring
    has been enabled by a prior event handler.
    """
    unique_conn = self.extract_conn_info(packet)

    if unique_conn not in self.timers.keys(): # connection is over (due to 30s limit).
      return

    ip_address = self.external_ip(unique_conn, reverse)
    port = self.external_port(unique_conn, reverse)
    if self.debug: log.debug("data: " + str(packet.payload.payload.payload))
    for monitor_string in self.monitor_strings[ip_address].keys():
      data = self.prev_html_data[ip_address][monitor_string] + str(packet.payload.payload.payload)
      if self.debug: log.debug("prev: " + self.prev_html_data[ip_address][monitor_string])
      
      self.prev_html_data[ip_address][monitor_string] = ""
      monitor_stringSearchObj = re.findall(monitor_string, data)
      self.monitor_strings[ip_address][monitor_string] += len(monitor_stringSearchObj)
      if self.debug: log.debug("in Monitor: " + str(self.monitor_strings))
  
      httpIndex = data.rfind(monitor_string[0])
      self.prev_html_data[ip_address][monitor_string] += monitor_string[0]
      if httpIndex >= 0:
        for monitor_stringIndex in range(1, len(monitor_string)): #remove -1 from this line since range is not inclusive
          if httpIndex + monitor_stringIndex >= len(data):
            break
          if data[httpIndex+monitor_stringIndex] == monitor_string[monitor_stringIndex] and monitor_stringIndex != len(monitor_string)-1: #keep negative 1 here (i'm pretty sure we didn't have it here when we were having problems, right?) because length-1 is last char in string, would explain why things weren't working before, without this it would never realize it found the entire string, so it would save the full word "bing"
            self.prev_html_data[ip_address][monitor_string] += monitor_string[monitor_stringIndex]
          else:
            self.prev_html_data[ip_address][monitor_string] = ""
            break
      
      self.timers[unique_conn].cancel()
      self.timers[unique_conn] = Timer(30, self.handle_closed_connection, args=(unique_conn, reverse))
      if self.debug: log.debug("timer created")

  def handle_closed_connection(self, unique_conn, reverse):
    ip_address = self.external_ip(unique_conn, reverse)
    port = self.external_port(unique_conn, reverse)

    if self.debug: log.debug("in connectionclos/ed")

    count = ip_address + "," + port + "," + "%s,%s\n"

    if self.debug: log.debug("self.monitor_strings[ip_address]: " + str(self.monitor_strings[ip_address]))
    for monitor_string in self.monitor_strings[ip_address].keys():
      self.counts_file.write(count % (monitor_string, self.monitor_strings[ip_address][monitor_string]))
      self.counts_file.flush()
      self.monitor_strings[ip_address][monitor_string] = 0

      if self.debug: log.debug("Writing..." + count % (monitor_string, self.monitor_strings[ip_address][monitor_string]))
    del self.timers[unique_conn]
    log.debug("I deleted a timer")
#test



# 3rd
# very weird keyboard. check ip address (if it is destin's)    
          
