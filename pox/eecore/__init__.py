from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent.revent import *
from heapq import heappush, heappop
import pox.lib.addresses as addresses
from pox.lib.packet import *
import time

log = core.getLogger("ee")

import logging
import logging.handlers
fw_log = core.getLogger("fw")

def addRemoteLogger(l, p):
  h = logging.handlers.DatagramHandler("127.0.0.1", p)
  h.makePickle = lambda record: h.format(record) + "\n"
  f = logging.Formatter(logging.BASIC_FORMAT)
  h.setFormatter(f)
  l.addHandler(h)

addRemoteLogger(fw_log, 9999)
addRemoteLogger(logging.getLogger(), 9998)


MAX_CONNECTIONS = 10000


PRIORITY_NORMAL = 10 #of.OFP_DEFAULT_PRIORITY
PRIORITY_ALL_TCP = PRIORITY_NORMAL - 1
PRIORITY_FLOOD_REST = PRIORITY_ALL_TCP - 1

LOCAL_NETWORK = addresses.parseCIDR("10.1.1.0/24")
INTERNAL_ADDRESS = addresses.IPAddr("10.1.1.1")


UNKNOWN_PORT = object()

#INSIDE_PORT = UNKNOWN_PORT
#OUTSIDE_PORT = UNKNOWN_PORT
#INTERNAL_PORT = UNKNOWN_PORT

INSIDE_PORT = ["uap0","eth0"]
OUTSIDE_PORT = "veth1"
INTERNAL_PORT = "veth1"


class ACTION_FORWARD: pass
class ACTION_DROP: pass
class ACTION_DENY: pass
class ACTION_DEFER: pass


class Action (object):
  def __init__ (self):#, in_port):
    self._action = ACTION_DROP
    self._monitor_forward = False
    self._monitor_backward = False

  def __str__ (self):
    s = self._action.__name__
    if self.monitor_forward: s += " MF"
    if self.monitor_backward: s += " MB"
    return s
  def __repr__ (self):
    return "<" + str(self) + ">"

  @property
  def monitor_forward (self):
    return self._monitor_forward and self.forward

  @monitor_forward.setter
  def monitor_forward (self, value):
    if value: self.forward = True
    self._monitor_forward = value

  @property
  def monitor_backward (self):
    return self._monitor_backward and self.forward

  @monitor_backward.setter
  def monitor_backward (self, value):
    if value: self.forward = True
    self._monitor_backward = value

  def __eq__ (self, other):
    raise "Ack"

  @property
  def defer (self):
    return self._action is ACTION_DEFER

  @defer.setter
  def defer (self, value):
    if value:
      self._action = ACTION_DEFER
    else:
      self._action = ACTION_DROP

  @property
  def deny (self):
    return self._action is ACTION_DENY

  @deny.setter
  def deny (self, value):
    if value:
      self._action = ACTION_DENY
    else:
      self._action = ACTION_DROP

  @property
  def drop (self):
    return self._action is ACTION_DROP

  @drop.setter
  def drop (self, value):
    if value:
      self._action = ACTION_DROP
    else:
      self._action = ACTION_FORWARD

  @property
  def forward (self):
    return self._action is ACTION_FORWARD

  @forward.setter
  def forward (self, value):
    if value:
      self._action = ACTION_FORWARD
    else:
      self._action = ACTION_DROP


class FlowSignature (object):
  def __repr__ (self):
    return "<FlowSignature " + str(self) + ">"

  def __str__ (self):
    return "{}:{}|{}:{}".format(self.src, self.srcport, self.dst, self.dstport)

  def __init__ (self, src, srcport, dst, dstport):
    self.src = src
    self.srcport = srcport
    self.dst = dst
    self.dstport = dstport
    self._match = None
    self._reverse = None

  def __hash__ (self):
    return self.src._value ^ self.dst._value ^ self.srcport ^ self.dstport

  def __eq__ (self, other):
    if not isinstance(other, FlowSignature): return False
    if self.src != other.src: return False
    if self.dst != other.dst: return False
    if self.srcport != other.srcport: return False
    if self.dstport != other.dstport: return False
    return True

  @property
  def is_reverse (self):
    if self._reverse is None:
      if self.dst.inNetwork(LOCAL_NETWORK):
        self._reverse = True
      else:
        self._reverse = False
        if not self.src.inNetwork(LOCAL_NETWORK):
          log.debug("Not forward OR reverse connection: " + str(self))
    return self._reverse

  @property
  def match (self):
    if self._match is None:
      self._match = of.ofp_match(
                                 nw_src = self.src,
                                 nw_dst = self.dst,
                                 tp_src = self.srcport,
                                 tp_dst = self.dstport,
                                 dl_type = ethernet.IP_TYPE,
                                 nw_proto = ipv4.TCP_PROTOCOL,
                                 )
    return self._match

  @classmethod
  def from_packet (cls, packet):
    try:
      assert packet.type == ethernet.IP_TYPE
      assert packet.next.protocol == ipv4.TCP_PROTOCOL
      return cls(packet.next.srcip, packet.next.next.srcport,
                 packet.next.dstip, packet.next.next.dstport)
    except:
      log.warning("Tried to create a FlowSignature from a non-TCP packet")
      return None

  @property
  def flipped (self):
    return FlowSignature(self.dst, self.dstport, self.src, self.srcport)


class Connection (object):
  def __init__ (self, sig, action, opaque = None):
    self.sig = sig
    self.sig_r = sig.flipped

    self.opaque = opaque

    self.time = time.time()
    self.idle_time = self.time

    self.action = action

  def __eq__ (self, other):
    if isinstance(other, Connection):
      return self.sig == other.sig
    # Assume it's a sig
    return self.sig == other

  def __str__ (self):
    return "<Connection %s>" % (self.sig,)



class ConnectionTable (object):
  def __init__ (self, gateway):
    self.table = {}
    self._timers = [] # a heap
    self._dead_timers = 0
    self.gateway = gateway

  def _clean_timers (self):
    t = []
    while len(self._timers):
      i = heappop(self._timers)
      if i[0] == i[1].idle_time:
        heappush(t, i)
    self._timers = t
    self._dead_timers = 0

  def get (self, sig):
    item = self.table.get(sig)
    if item is None:
      item = self.table.get(sig.flipped)
    return item

  def refresh (self, sig_or_connection, buffer_reverse = False, buffer_id = None, data = None):
    if isinstance(sig_or_connection, Connection):
      sig = sig_or_connection.sig
    else:
      sig = sig_or_connection
    c = self.get(sig)

    self._dead_timers += 1
    if self._dead_timers > 50:
      self._clean_timers()

    heappush(self._timers, (c.idle_time, c))

    self.push_flows(c, buffer_reverse, buffer_id, data)

  def add_connection (self, sig, action, opaque, buffer_reverse = False, buffer_id = None, data = None):
    if sig.is_reverse:
      sig = sig.flipped

    if self._dead_timers > 50:
      self._clean_timers()

    # Clear space if necessary
    while len(self.table) > MAX_CONNECTIONS:
      i = heappop(self._timers)
      if i[0] == i[1].idle_time:
        if i[1].sig in self.table:
          t1 = time.time() - i[1].idle_time
          t2 = time.time() - i[1].time
          if t1 < 60 * 60 * 2.1:
            log.warning("%s was forced out after only %i seconds",
                        str(i[1].sig), t1)
          log.info("%s was forced out after %i seconds (%i idle)",
                   str(i[1].sig), t2, t1)
          del self.table[i[1].sig]

    c = Connection(sig, action, opaque)
    self.table[sig] = c
    heappush(self._timers, (c.idle_time, c))

    self.push_flows(c, buffer_reverse, buffer_id, data)

    return c

  def push_flows (self, con, buffer_reverse = False, buffer_id = None, data = None):
    if con.action.defer: return
    count = 0

    msg = of.ofp_flow_mod()
    msg.match = con.sig_r.match
    msg.match.in_port = OUTSIDE_PORT
    msg.idle_timeout = 10
    msg.hard_timeout = 60 * 2
    if con.action.forward:
      count += 1
      msg.actions.append(of.ofp_action_output(port = INSIDE_PORT))
      if buffer_id is not None and buffer_reverse:
        msg.buffer_id = buffer_id
      if (data is not None) and (buffer_reverse) and (buffer_id == -1):
        self.gateway.switch.send(of.ofp_packet_out(
         action = of.ofp_action_output(port = INSIDE_PORT),
         data = data))
    if con.action.monitor_backward:
      count += 1
      msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    self.gateway.switch.send(msg)

    msg = of.ofp_flow_mod()
    msg.match = con.sig.match
    msg.match.in_port = INSIDE_PORT
    msg.idle_timeout = 10 #FIXME: make 10 (and above too)
    msg.hard_timeout = 60 * 2
    if con.action.forward:
      count += 1
      msg.actions.append(of.ofp_action_output(port = OUTSIDE_PORT))
      if buffer_id is not None and not buffer_reverse:
        msg.buffer_id = buffer_id
      if (data is not None) and (not buffer_reverse) and (buffer_id == -1):
        self.gateway.switch.send(of.ofp_packet_out(
         action = of.ofp_action_output(port = OUTSIDE_PORT),
         data = data))
    if con.action.monitor_forward:
      count += 1
      msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    self.gateway.switch.send(msg)

    log.debug("Pushed %i rules for %s", count, str(con))


class MonitorData (Event):
  def __init__ (self, packet, connection):
    Event.__init__(self)
    self.connection = connection
    self.packet = packet
    self.opaque = connection.opaque

  def _invoke (self, handler, *args, **kw):
    reverse = self.packet.next.srcip == self.connection.sig.dst
    r = handler(self, self.packet, reverse)
    self.connection.opaque = self.opaque
    return r


class ConnectionIn (Event):
  def __init__ (self, packet, sig):
    Event.__init__(self)
    self.packet = packet
    #self.port = port
    #self.dest_port =

    self.sig = sig
    self.action = Action()

    self.opaque = None

  def _invoke (self, handler, *args, **kw):
    r = handler(self, self.sig, self.packet)
    return r


class DeferredConnectionIn (ConnectionIn):
  def __init__ (self, packet, connection):
    Event.__init__(self)
    self.packet = packet
    self.connection = connection
    self.sig = connection.sig
    self.action = connection.action
    self.opaque = connection.opaque

  def _invoke (self, handler, *args, **kw):
    r = handler(self, self.sig, self.packet)
    self.connection.opaque = self.opaque
    return r


class EE122Gateway (EventMixin):
  _eventMixin_events = set([
    DeferredConnectionIn,
    ConnectionIn,
    MonitorData,
  ])

  def __init__ (self, switch, ports):
    global INSIDE_PORT, OUTSIDE_PORT, INTERNAL_PORT
    for p in ports:
      if p.name == OUTSIDE_PORT:
        OUTSIDE_PORT = p.port_no
      if isinstance(INSIDE_PORT, list) and p.name in INSIDE_PORT:
        INSIDE_PORT = p.port_no
      if p.name == INTERNAL_PORT:
        INTERNAL_PORT = p.port_no

    self.switch = switch

    # We want to hear PacketIn messages, so we listen
    self.listenTo(switch)

    # Catch all TCP traffic
    msg = of.ofp_flow_mod()
    msg.cookie = 1
    msg.match.dl_type = ethernet.IP_TYPE
    msg.match.nw_proto = ipv4.TCP_PROTOCOL
    msg.priority = PRIORITY_ALL_TCP
    msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    self.switch.send(msg)

    # Make communication between the internal address automatic...
    msg = of.ofp_flow_mod()
    msg.cookie = 2
    msg.match.dl_type = ethernet.IP_TYPE
    msg.match.nw_proto = ipv4.TCP_PROTOCOL
    msg.match.nw_src = INTERNAL_ADDRESS
    msg.match.in_port = INTERNAL_PORT
    msg.priority = PRIORITY_NORMAL
    msg.actions.append(of.ofp_action_output(port = INSIDE_PORT))
    self.switch.send(msg)

    msg = of.ofp_flow_mod()
    msg.cookie = 3
    msg.match.dl_type = ethernet.IP_TYPE
    msg.match.nw_proto = ipv4.TCP_PROTOCOL
    msg.match.nw_dst = INTERNAL_ADDRESS
    msg.match.in_port = INSIDE_PORT
    msg.priority = PRIORITY_NORMAL
    msg.actions.append(of.ofp_action_output(port = INTERNAL_PORT))
    self.switch.send(msg)


    # Flood other traffic
    #TODO: have two versions of this rule based on in_port so that the one
    #      from wifi can also send back out over wifi when the internal wifi
    #      bridge is disabled.
    msg = of.ofp_flow_mod()
    msg.cookie = 4
    #msg.match.in_port = 0
    msg.priority = PRIORITY_FLOOD_REST
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    self.switch.send(msg)

    self.table = ConnectionTable(self)


  def _handle_PacketIn (self, event):
    def do_monitor (connection, eth, reverse, loud=False):
      if loud:
        print connection.action, reverse, flow
      if ( (connection.action.monitor_forward and not reverse) or
           (connection.action.monitor_backward and reverse) ):
        ev = MonitorData(eth, connection)
        self.raiseEvent(ev)
        return True
      return False

    def kill_buffer ():
      if event.ofp.buffer_id == -1: return
      msg = of.ofp_packet_out()
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.switch.send(msg)
      return

    eth = event.parsed
    tcpp = eth.find('tcp')
    if tcpp is None:
      log.warning("PacketIn of a non-TCP packet")
      return kill_buffer()

    flow = FlowSignature.from_packet(eth)
    orig_flow = flow
    if flow.is_reverse: flow = flow.flipped
    connection = self.table.get(flow)

    reverse = orig_flow.is_reverse

    if connection:
      if connection.action.defer:
        if len(tcpp.payload) == 0 or tcpp.SYN:
          msg = of.ofp_packet_out()
          msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
          msg.buffer_id = event.ofp.buffer_id
          if msg.buffer_id == -1: msg.data = event.data
          msg.in_port = event.port
          self.switch.send(msg)
          return
        else: #xxx
          connection.action.drop = True
          ev = DeferredConnectionIn(eth, connection)
          self.raiseEvent(ev)
          if connection.action.defer:
            log.error("Can't defer a deferred connection!")
            connection.action.drop = True

          if ev.action.deny:
            log.debug("Denying %s", flow)
            deny = tcp(srcport=tcpp.dstport, dstport=tcpp.srcport)
            deny.RST = True
            deny.ACK = True
            deny.ack = tcpp.seq + len(tcpp.payload)
            deny.seq = tcpp.ack
            deny.off = deny.MIN_LEN/4
            deny_packet = ethernet(src=eth.dst, dst=eth.src, type=eth.type,
             payload=ipv4(srcip=eth.find('ipv4').dstip,
             dstip=eth.find('ipv4').srcip,
             protocol=ipv4.TCP_PROTOCOL, payload=deny))
            self.switch.send(of.ofp_packet_out(data = deny_packet.pack(),
             action = of.ofp_action_output(port = event.port)))

          self.table.refresh(connection, reverse, event.ofp.buffer_id,
                             event.data)
          do_monitor(connection, eth, reverse)
          return

      if do_monitor(connection, eth, reverse, False):
        return kill_buffer()
    #elif event.ofp.reason == of.OFPR_ACTION:
    #  log.warning("Packet via OFPR_ACTION but don't have flow for %s", flow)
    #  return kill_buffer()

    if not tcpp.SYN:
      if connection is None:
        if tcpp.FIN or tcpp.RST:
          if tcpp.FIN:
            if tcpp.RST:
              s = "FIN+RST"
            else:
              s = "FIN"
          else:
            s = "RST"
          log.info("%s for missing connection %s", s, orig_flow)
          #TODO: strip payload?
          msg = of.ofp_packet_out()
          msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
          msg.buffer_id = event.ofp.buffer_id
          if msg.buffer_id == -1: msg.data = event.data
          msg.in_port = event.port
          self.switch.send(msg)
          return
        else:
          log.warning("Drop mid-connection packet for %s", orig_flow)
          return kill_buffer()
      else:
        # Use existing
        self.table.refresh(connection, reverse, event.ofp.buffer_id, event.data)
        return

    # We don't know this connection
    ev = ConnectionIn(eth, flow)
    self.raiseEvent(ev)
    if ev.action.deny:
      deny = tcp(srcport=tcpp.dstport, dstport=tcpp.srcport)
      deny.RST = True
      deny.ACK = True
      #deny.SYN = True
      deny.ack = tcpp.seq + 1
      deny.seq = 0xaddedead
      deny.off = deny.MIN_LEN/4
      deny_packet = ethernet(src=eth.dst, dst=eth.src, type=eth.type, payload=
       ipv4(srcip=eth.find('ipv4').dstip, dstip=eth.find('ipv4').srcip,
       protocol=ipv4.TCP_PROTOCOL, payload=deny))
      self.switch.send(of.ofp_packet_out(data = deny_packet.pack(),
       action = of.ofp_action_output(port = event.port)))

    connection = self.table.add_connection(flow, ev.action, ev.opaque, reverse,
                                           event.ofp.buffer_id, event.data)
    do_monitor(connection, eth, reverse)



def launch ():
  def _handle_ConnectionUp (event):
    #log.debug("Connection %s" % (event.connection,))
    gw = EE122Gateway(event.connection, event.ofp.ports)
    core.register("gateway", gw)
    #gw.addListeners(Controller())
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)

  def _handle_reg (event):
    if event.name == "gateway":
      try:
        from firewall import Firewall
        event.component.addListeners(Firewall())
      except:
        fw_log.exception("Couldn't load firewall.py")
  core.addListenerByName("ComponentRegistered", _handle_reg)

