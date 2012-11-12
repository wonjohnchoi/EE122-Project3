from pox.core import core
from pox.lib.addresses import * 
from pox.lib.packet import *
from pox.lib.recoco.recoco import Timer
import re


# Get a logger
log = core.getLogger("fw")

class Firewall (object):
  """
  Firewall class.
  Extend this to implement some firewall functionality.
  Don't change the name or anything -- the eecore component
  expects it to be firewall.Firewall.
  """
  
  def __init__(self):
    """
    Constructor.
    Put your initialization code here.
    """
    self.bannedPorts = set()
    bannedPortsFile = open('/root/pox/ext/banned-ports.txt', 'r')
    for portNumber in bannedPortsFile:
      self.bannedPorts.add(int(portNumber.rstrip()))
    bannedPortsFile.close()

    self.bannedDomains = set()
    bannedDomainsFile = open('/root/pox/ext/banned-domains.txt', 'r')
    for domain in bannedDomainsFile:
      self.bannedDomains.add(str(domain.rstrip()))
    bannedDomainsFile.close()

    self.previousPacket = dict()
    self.monitorStrings = dict()
    self.timers = dict()
    monitoredStringsFile = open('/root/pox/ext/monitored-strings.txt', 'r')
    for pair in monitoredStringsFile:
      ip, mString = pair.split(':')
      ip = str(ip)
      if ip in self.monitorStrings.keys():
        self.monitorStrings[ip][str(mString.rstrip())] = 0
        self.previousPacket[ip][str(mString.rstrip())] = ""
      else:
        newDict = dict()
        packetDict = dict()
        newDict[str(mString.rstrip())] = 0
        packetDict[str(mString.rstrip())] = ""
        self.monitorStrings[ip] = newDict
        self.previousPacket[ip] = packetDict
    monitoredStringsFile.close()

    log.debug("Firewall initialized.")

  def _handle_ConnectionIn (self, event, flow, packet):
    """
    New connection event handler.
    You can alter what happens with the connection by altering the
    action property of the event.
    """
    if flow.dstport in self.bannedPorts:
      log.debug("Denied connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
      event.action.forward = False
    else:
      log.debug("Deferred connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
      event.action.defer = True

  def _handle_DeferredConnectionIn (self, event, flow, packet):
    """
    Deferred connection event handler.
    If the initial connection handler defers its decision, this
    handler will be called when the first actual payload data
    comes across the connection.
    """
    #log.debug(str(packet.payload.payload.payload))
    packetHostNameRegex = re.search('Host: ([^\s]+)', packet.payload.payload.payload)
    if packetHostNameRegex is None:
      if flow.dst in self.monitorStrings.keys():
        log.debug("Monitored connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
        event.action.monitor_forward = True
        event.action.monitor_backward = True
      log.debug("Allowed connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
      event.action.forward = True
    packetHostName = packetHostNameRegex.group(0)[6:]
    for domain in self.bannedDomains:
      if domain == packetHostName:
        log.debug("Denied connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
        event.action.forward = False
        return
      if len(packetHostName) > len(domain) and packetHostName[(len(packetHostName)-len(domain)):len(packetHostName)] == domain:
        if packetHostName[len(packetHostName)-len(domain)-1] == '.':
          log.debug("Denied connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
          event.action.forward = False
          return       
    if flow.dst in self.monitorStrings.keys():
      log.debug("Monitored connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
      event.action.monitor_forward = True
      event.action.monitor_backward = True
    log.debug("Allowed connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
    event.action.forward = True
    
  def _handle_MonitorData (self, event, packet, reverse):
    """
    Monitoring event handler.
    Called when data passes over the connection if monitoring
    has been enabled by a prior event handler.
    """
    ipAddress = packet.payload.dstip
    port = packet.payload.payload.dstport
    if reverse:
      ipAddress = packet.payload.srcip
      port = packet.payload.payload.srcport
    httpData = packet.payload.payload.payload

    if ipAddress in self.timers.keys():
      self.timers[ipAddress].cancel()

    currentDict = self.monitorStrings[str(ipAddress)]
    for searchString in currentDict.keys():
      data = self.previousPacket[str(ipAddress)][searchString] + httpData
      log.debug("data" + data)
      self.previousPacket[str(ipAddress)][searchString] = ""
      searchStringSearchObj = re.findall('%s' % searchString, data)
      currentDict[searchString] += len(searchStringSearchObj)
      log.debug("in Monitor: " + str(self.monitorStrings))
      seenSoFar = ""
      httpIndex = data.rfind(searchString[0])
      self.previousPacket[str(ipAddress)][searchString] += searchString[0]
      if httpIndex >= 0:
        for searchStringIndex in range(1, len(searchString)): #remove -1 from this line since range is not inclusive
          if httpIndex + searchStringIndex >= len(data):
            break
          if data[httpIndex+searchStringIndex] == searchString[searchStringIndex] and searchStringIndex != len(searchString)-1: #keep negative 1 here (i'm pretty sure we didn't have it here when we were having problems, right?) because length-1 is last char in string, would explain why things weren't working before, without this it would never realize it found the entire string, so it would save the full word "bing"
            self.previousPacket[str(ipAddress)][searchString] += searchString[searchStringIndex]
          else:
            self.previousPacket[str(ipAddress)][searchString] = ""
            break    

      log.debug("timers")
      self.timers[ipAddress] = Timer(5.0, self.handle_ConnectionClosed, args=(ipAddress, port))
      log.debug("timer created")

  def handle_ConnectionClosed(self, ipAddress, destPort):
    log.debug("in connectionclos/ed")
    writeFile = open('/root/pox/ext/counts.txt', 'a')
    line = str(ipAddress) + "," + str(destPort) + ","
    log.debug("line: " + line)
    currentDict = self.monitorStrings[str(ipAddress)]
    log.debug("currentDict: " + str(currentDict))
    for searchString in currentDict.keys():
      val = currentDict[searchString]
      addLine = line + searchString + "," + str(val) + '\n'
      log.debug("addline: " + addLine)
      writeFile.write(addLine)
      currentDict[searchString] = 0
      log.debug("I wrote to the file")
