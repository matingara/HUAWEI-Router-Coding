#!/usr/bin/python
#coding=utf-8
import json
import re
import myconsts as const
import predefined as predefined
import sys
import os
import datetime
import collections

#fix UnicodeDecodeError
reload(sys)  
sys.setdefaultencoding('utf-8')

const.NONE = 0
const.CMD_VERSION = 0x100
const.CMD_CONFIG  = 0x200
const.CMD_ROUTE   = 0x400
const.CMD_SEC_POLICY = 0x201
const.CMD_NAT_POLICY = 0x202
const.CMD_ADDRSET    = 0x203
const.CMD_SERVICE    = 0x204
const.CMD_INTERFACE  = 0x205
const.CMD_ZONE  	 = 0x206
const.CMD_SCHEDULE   = 0x207
const.REGEX_MAC  = "([0-9a-fA-F]{1,4}-[0-9a-fA-F]{1,4}-[0-9a-fA-F]{1,4})"
const.REGEX_IPV4 = "(\d+.\d+.\d+.\d+)"
const.REGEX_IPV6 = "(([0-9a-fA-F]{1,4}:){1,7}(:?[0-9a-fA-F]{1,4}){1,7})"
const.REGEX_NAME = "([^\" ]+|\"[^\"]+\")"
const.REGEX_DATE = "(\d{2}:\d{2}:\d{2} \d{4}\/\d{1,2}\/\d{1,2})"

const.ICMP_PREFIX = "ICMP: "
const.ICMPV6_PREFIX = "ICMPv6: "
const.GEO_PREFIX = "region_"
const.GEOSET_PREFIX = "region_grp_"
const.UNSUPPORTED = "unsupported_"
const.JSON_FILENAME = "config_parser.json"
const.OK = 0
const.ERR = 1
const.ANY = "any"
const.ANYPORT = "*"
const.TELNETSTR = "2D                                          2D"

class Object():
	comment = ""

	def setComment(self, comment):
		self.comment = comment
	def getComment(self):
		return self.comment

	def __init__(self):
		self.cleanAll()

	def cleanAll(self):
		self.comment = ""
		return

	def getJsonData(self):
		return

rulecount = 0
natrulecount = 0
#define policy rule 
class CommonPolicyRule(Object):
	rule_id = None
	rule_name = None
	action = ""
	src_zone_list = []
	dst_zone_list = []
	src_addr_list = []
	dst_addr_list = []
	service_list = []
	timeschedule = const.ANY
	enable = "enabled" #or "disabled"

	def __init__(self):
		self.cleanAll()

	def setRuleID(self, rule_id):
		self.rule_id = rule_id
	def getRuleID(self):
		return self.rule_id
	def setRuleName(self, rule_name):
		self.rule_name = rule_name
	def getRuleName(self):
		return self.rule_name
	def setEnable(self, flag):
		self.enable = flag
	def getEnable(self):
		return self.enable
	def setAction(self, action):
		self.action = action
	def getAction(self):
		return self.action
	def appendSrcZone(self, src):
		self.src_zone_list.append(src)
	def getSrcZone(self):
		return self.src_zone_list
	def appendDstZone(self, dst):
		self.dst_zone_list.append(dst)
	def getDstZone(self):
		return self.dst_zone_list
	def appendSrcAddr(self, src):
		self.src_addr_list.append(src)
	def getSrcAddr(self):
		return self.src_addr_list
	def appendDstAddr(self, dst):
		self.dst_addr_list.append(dst)
	def getDstAddr(self):
		return self.dst_addr_list
	def appendService(self, service):
		self.service_list.append(service)
	def getService(self):
		return self.service_list
	def setTimeSchedule(self, timeschedule):
		self.timeschedule = timeschedule
	def getTimeSchedule(self):
		return self.timeschedule

	def cleanCommonAll(self):
		self.comment = ""
		self.rule_id = None
		self.rule_name = None
		self.action = ""
		self.src_zone_list = []
		self.dst_zone_list = []
		self.src_addr_list = []
		self.dst_addr_list = []
		self.service_list = []
		self.timeschedule = const.ANY
		self.enable = "enabled"

	def getCommonJsonData(self):
		if(None == self.getRuleName()):
			return None

		rule_dict = collections.OrderedDict()
		rule_dict["rule_name"] = self.getRuleName()
		rule_dict["rule_display_name"] = self.getRuleName()
		rule_dict["rule_id"] = self.getRuleName()

		rule_dict["description"] = self.getComment()
		rule_dict["enable"] = self.getEnable()
		rule_dict["action"] = self.getAction()

		rule_dict.setdefault("src_zone", [const.ANY])
		if(len(self.src_zone_list) > 0):
			rule_dict["src_zone"] = self.getSrcZone()
		rule_dict.setdefault("dst_zone", [const.ANY])
		if(len(self.dst_zone_list) > 0):
			rule_dict["dst_zone"] = self.getDstZone()
		rule_dict.setdefault("src", [const.ANY])
		if(len(self.src_addr_list) > 0):
			rule_dict["src"] = self.getSrcAddr()
		rule_dict.setdefault("dst", [const.ANY])
		if(len(self.dst_addr_list) > 0):
			rule_dict["dst"] = self.getDstAddr()
		rule_dict.setdefault("service", [const.ANY])
		if(len(self.service_list) > 0):
			rule_dict["service"] = self.getService()
		rule_dict["schedule"] = self.getTimeSchedule()

		return rule_dict

class SecPolicyRule(CommonPolicyRule):
	syslog = "0" #or "1"
	parentgroup = ""

	def __init__(self):
		self.cleanAll()

	def setSyslog(self, flag):
		self.syslog = flag
	def getSyslog(self):
		return self.syslog
	def setParentGroup(self, group):
		self.parentgroup = group
	def getParentGroup(self):
		return self.parentgroup

	def cleanAll(self):
		self.cleanCommonAll()
		self.syslog = "0"
		self.parentgroup = ""

	def getJsonData(self):
		if(None == self.getRuleName()):
			return None

		rule_dict = self.getCommonJsonData()
		rule_dict["rule_grp"] = self.getParentGroup()
		rule_dict["log"] = self.getSyslog()

		return rule_dict

class NatPolicyRule(CommonPolicyRule):
	nattype = ""
	egressinterface = ""

	def __init__(self):
		self.cleanAll()

	def setNatType(self, nattype):
		self.nattype = nattype
	def getNatType(self):
		return self.nattype
	def setEgressInterface(self, egressinterface):
		self.egressinterface = egressinterface
	def getEgressInterface(self):
		return self.egressinterface

	def cleanAll(self):
		self.cleanCommonAll()
		self.nattype = ""
		self.egressinterface = ""

	def getJsonData(self):
		if(None == self.getRuleName()):
			return None

		rule_dict = self.getCommonJsonData()
		
		return rule_dict

class RuleGroup(Object):
	name = None
	enable = "enabled"

	def setName(self, name):
		self.name = name
	def getName(self):
		return self.name
	def setEnable(self, flag):
		self.enable = flag
	def getEnable(self):
		return self.enable
	
	def cleanAll(self):
		self.comment = ""
		self.name = None
		self.enable = "enabled"

	def getJsonData(self):
		if(None == self.getName()):
			return None

		rule_dict = collections.OrderedDict()
		rule_dict["id"] = self.getName()
		rule_dict["name"] = self.getName()
		rule_dict["enable"] = self.getEnable()
		rule_dict["description"] = self.getComment()
		rule_dict["rule_display_name"] = self.getName()
		
		return rule_dict

class Route(Object):
	route_id = None
	route = None
	route_mask = None
	gateway = None
	interface = None

	def __init__(self):
		self.cleanAll()
	def setId(self, route_id):
		self.route_id = route_id
	def getId(self):
		return self.route_id
	def setRoute(self, route):
		self.route = route
	def getRoute(self):
		return self.route
	def setRouteMask(self, route_mask):
		self.route_mask = route_mask
	def getRouteMask(self):
		return self.route_mask
	def setGateway(self, gateway):
		self.gateway = gateway
	def getGateway(self):
		return self.gateway
	def setInterface(self, interface):
		self.interface = interface
	def getInterface(self):
		return self.interface
	def cleanAll(self):
		self.route_id = None
		self.route = None
		self.route_mask = None
		self.gateway = None
		self.interface = None
		self.comment = ""

	def getJsonData(self):
		if(None == self.getId()):
			return None

		route_dict = collections.OrderedDict()
		route_dict["id"] = self.getId()
		route_dict["route"] = self.getRoute()
		route_dict["route_mask"] = self.getRouteMask()
		route_dict["gateway"] = self.getGateway()
		route_dict["interface"] = self.getInterface()

		return route_dict

class AddressSet(Object):
	name = None
	iptype = "" #<PREDEFINED|ANY|IP_ADDRESS|IP_RANGE|DOMAIN|SUBNET|INTERNAL|IPS_LIST>
	ip_list = []

	def __init__(self):
		self.cleanAll()
	def setName(self, name):
		self.name = name
	def getName(self):
		return self.name
	def setIPType(self, iptype):
		self.iptype = iptype
	def getIPType(self):
		return self.iptype
	def appendIPList(self, ip):
		self.ip_list.append(ip)
	def getIPList(self):
		return self.ip_list

	def cleanAll(self):
		self.name = None
		self.comment = ""
		self.iptype = ""
		self.ip_list = []
	
	def getJsonData(self):
		if(None == self.getName()):
			return None

		addrset_dic = collections.OrderedDict()
		addrset_dic["name"] = self.getName()
		addrset_dic["comment"] = self.getComment()
		if("GROUP" == self.getIPType()):
			addrset_dic["members"] = self.getIPList()
		else:
			addrset_dic["ips"] = self.getIPList()
		addrset_dic["type"] = self.getIPType()

		return addrset_dic

class ServiceSet(Object):
	name = None
	servicetype = "" #<ANY|TCP|UDP|ICMP|TCP_UDP|INTERNAL|GROUP>
	service_list = []

	def __init__(self):
		self.cleanAll()
	def setName(self, name):
		self.name = name
	def getName(self):
		return self.name
	def setServiceType(self, servicetype):
		self.servicetype = servicetype
	def getServiceType(self):
		return self.servicetype
	def setServiceList(self, service_list):
		self.service_list = service_list
	def appendServiceList(self, service):
		self.service_list.append(service)
	def getServiceList(self):
		return self.service_list

	def cleanAll(self):
		self.name = None
		self.comment = ""
		self.servicetype = ""
		self.service_list = []
	
	def getJsonData(self):
		if(None == self.getName()):
			return None

		service_dic = collections.OrderedDict()	
		service_dic["name"] = self.getName()
		service_dic["comment"] = self.getComment()
		if("GROUP" == self.getServiceType()):
			service_dic["members"] = self.getServiceList()
		else:
			service_dic["service_definitions"] = self.getServiceList()
		service_dic["type"] = self.getServiceType()

		return service_dic

class TimeSchedule(Object):
	name = None
	start_date = None
	end_date = None

	def __init__(self):
		self.cleanAll()
	def setName(self, name):
		self.name = name
	def getName(self):
		return self.name
	def setStartDate(self, start_date):
		self.start_date = start_date
	def getStartDate(self):
		return self.start_date
	def setEndDate(self, end_date):
		self.end_date = end_date
	def getEndDate(self):
		return self.end_date

	def cleanAll(self):
		self.name = None
		self.start_date = None
		self.end_date = None
	
	def getJsonData(self):
		if(None == self.getName()):
			return None

		schedule_dict = collections.OrderedDict()
		schedule_dict["name"] = self.getName()
		if(self.getStartDate()):
			schedule_dict["start_date"] = self.getStartDate()

		if(self.getEndDate()):
			schedule_dict["end_date"] = self.getEndDate()

		return schedule_dict

class Interface(Object):
	name = None
	ip_list = []
	zone = ""
	enable = None#v1 and v5 has different default value

	def __init__(self):
		self.cleanAll()
	def setName(self, name):
		self.name = name
	def getName(self):
		return self.name
	def appendIPList(self, ip):
		self.ip_list.append(ip)
	def getIPList(self):
		return self.ip_list
	def setZone(self, zone):
		self.zone = zone
	def getZone(self):
		return self.zone
	def setEnable(self, enable):
		self.enable = enable
	def getEnable(self):
		return self.enable
	
	def cleanAll(self):
		self.name = None
		self.ip_list = []
		self.zone = ""
		self.comment = ""
		self.enable = None
	
	def getJsonData(self):
		if(None == self.getName()):
			return None

		intf_dict = collections.OrderedDict()
		intf_dict["name"] = self.getName()
		if("" == self.getComment() and "GigabitEthernet0/0/0" == self.getName()):
			self.setComment("GE0/MGMT")
		intf_dict["description"] = self.getComment()
		intf_dict["enable"] = self.getEnable()
		intf_dict["ips"] = self.getIPList()
		intf_dict["zone"] = self.getZone()

		return intf_dict

class Zone(Object):
	name = None
	interface_list = []

	def __init__(self):
		self.cleanAll()
	def setName(self, name):
		self.name = name
	def getName(self):
		return self.name
	def appendInterface(self, interface):
		self.interface_list.append(interface)
	def getInterface(self):
		return self.interface_list
	
	def cleanAll(self):
		self.name = None
		self.interface_list = []
		self.comment = ""

	def getJsonData(self):
		if(None == self.getName()):
			return None

		zone_dict = collections.OrderedDict()
		zone_dict["name"] = self.getName()
		zone_dict["description"] = self.getComment()
		zone_dict["interfaces"] = self.getInterface()

		return zone_dict

class DeviceInformation(Object):
	hostname = None
	major_version = ""
	version = None
	minor_version = ""

	def setHostName(self, hostname):
		self.hostname = hostname
	def getHostName(self):
		return self.hostname
	def setMajorVersion(self, major_version):
		self.major_version = major_version
	def getMajorVersion(self):
		return self.major_version
	def setVersion(self, version):
		self.version = version
	def getVersion(self):
		return self.version
	def setMinorVersion(self, minor_version):
		self.minor_version = minor_version
	def getMinorVersion(self):
		return self.minor_version

	def getJsonData(self):
		device_dict = collections.OrderedDict()
		device_dict["name"] = self.getHostName()
		device_dict["major_version"] = self.getMajorVersion()
		device_dict["version"] = self.getVersion()
		device_dict["minor_version"] = self.getMinorVersion()

		return device_dict

class IPConvert():
	def convertMaskToMaskLen(self, mask):
		mask_splited = mask.split(".")
		zero_flag = 0
		mask_len = 0
		for single in mask_splited:
			dot_bin = bin(int(single))[2:].zfill(8)
			for i in dot_bin:
				if('0' == i):
					zero_flag = 1
				else:
					mask_len += 1
					if(1 == zero_flag):
						return -1
		return mask_len
		
	def convertWildcardMaskToMask(self, wild_mask):
		mask_splited = wild_mask.split(".")
		mask_uint = ''
		for i in mask_splited:
			mask_uint += str(255 - int(i)) + '.'
		return mask_uint[:-1]

	def convertPortRange(self, old_port):
		new_port = old_port.strip().replace(" to ", "-").split(" ")
		return new_port

	def convertService(self, old_service):
		if("sctp" == old_service):
			return "132"
		if("icmpv6" == old_service):
			return "58"
		return old_service

	def convertICMPandICMPv6(self, icmptype, content):
		if("icmp" == icmptype):
			return "%s%s" %(const.ICMP_PREFIX, content)
		else:
			return "%s%s" %(const.ICMPV6_PREFIX, content)

#define parser parent
class CmdParser():

	def parseCmd(self, cmd, root_dict):
		return const.ERR

	def isEnd(self, cmd):
		return 0
		
	def ignoreQuotation(self, str):
		if(None == str):
			return str
		n = len(str)
		if(n < 3):
			return str
		if((str[0] == '"') and (str[-1] == '"')):
			return str[1:n-1]
		return str

class PolicyCmdParser(CmdParser):
	rule = CommonPolicyRule()

	def parseZone(self, elements):
		pattern = "^%s" %const.REGEX_NAME
		matchObj = re.match(pattern, elements)
		if(matchObj):
			zone_name = self.ignoreQuotation(matchObj.group(1))
			return zone_name
		return None

	def parseAddress(self, elements, root_dict):
		parser = AddressSetCmdParser()
		#ip masklen
		pattern = "^%s (\d+)( description .+)?$" %(const.REGEX_IPV4)
		matchObj = re.match(pattern, elements)
		if(matchObj):
			ipv4 = matchObj.group(1) + "/" + matchObj.group(2)
			return  parser.createInternalHosts(root_dict, ipv4)

		#ip mask
		pattern = "^%s mask %s( description .+)?$" %(const.REGEX_IPV4, const.REGEX_IPV4)
		matchObj = re.match(pattern, elements)
		if(matchObj):
			masklen = IPConvert().convertMaskToMaskLen(matchObj.group(2))
			if(0 > masklen):
				return const.UNSUPPORTED + "wildcard_%s/%s" %(matchObj.group(1), matchObj.group(2))
			ipv4 = matchObj.group(1) + "/" + str(masklen)
			return parser.createInternalHosts(root_dict, ipv4)

		#wildcard mask
		pattern = "^%s %s( description .+)?$" %(const.REGEX_IPV4, const.REGEX_IPV4)
		matchObj = re.match(pattern, elements)
		if(matchObj):
			mask = IPConvert().convertWildcardMaskToMask(matchObj.group(2))
			masklen = IPConvert().convertMaskToMaskLen(mask)
			if(0 > masklen):
				return const.UNSUPPORTED + "wildcard_%s\%s" %(matchObj.group(1), matchObj.group(2))
			ipv4 = matchObj.group(1) + "/" + str(masklen)
			return parser.createInternalHosts(root_dict, ipv4)
		
		#ip range
		pattern = "^range %s %s( description .+)?$" %(const.REGEX_IPV4, const.REGEX_IPV4)
		matchObj = re.match(pattern, elements)
		if(matchObj):
			ipv4 = matchObj.group(1) + '-' + matchObj.group(2)
			return parser.createInternalHosts(root_dict, ipv4)

		pattern = "^address-set %s( description .+)?$" %const.REGEX_NAME
		matchObj = re.match(pattern, elements)
		if(matchObj):
			addrset_name = self.ignoreQuotation(matchObj.group(1))
			return addrset_name	
		
		pattern = "^domain-set %s( description .+)?$" %const.REGEX_NAME
		matchObj = re.match(pattern, elements)
		if(matchObj):
			domainset = self.ignoreQuotation(matchObj.group(1))
			return const.UNSUPPORTED + "domainset_" + domainset	
		
		pattern = "^geo-location %s( description .+)?$" %const.REGEX_NAME
		matchObj = re.match(pattern, elements)
		if(matchObj):
			geo_location = self.ignoreQuotation(matchObj.group(1))
			return const.GEO_PREFIX + geo_location

		pattern = "^geo-location-set %s( description .+)?$" %const.REGEX_NAME
		matchObj = re.match(pattern, elements)
		if(matchObj):
			geo_locationset = self.ignoreQuotation(matchObj.group(1))
			return const.GEOSET_PREFIX + geo_locationset

		#mac
		pattern = "^%s( description .+)?" %const.REGEX_MAC
		matchObj = re.match(pattern, elements)
		if(matchObj):
			mac = matchObj.group(1)
			return const.UNSUPPORTED + "mac_" + mac

		#ipv6 len
		pattern = "^%s (\d{1,3})( description .+)?" %const.REGEX_IPV6
		matchObj = re.match(pattern, elements)
		if(matchObj):
			ipv6 = "%s/%s" %(matchObj.group(1), matchObj.group(4))
			return const.UNSUPPORTED + "ipv6_" + ipv6

		#ipv6 range
		pattern = "^range %s %s( description .+)?" %(const.REGEX_IPV6, const.REGEX_IPV6)
		matchObj = re.match(pattern, elements)
		if(matchObj):
			ipv6 = "%s-%s" %(matchObj.group(1), matchObj.group(4))
			return const.UNSUPPORTED + "ipv6_" + ipv6

		return None

	def parseService(self, elements, root_dict):
		pattern = "^protocol (icmp|icmpv6|sctp|tcp|udp)( description .+)?$"
		matchObj = re.match(pattern, elements)
		if(matchObj):
			protocol = matchObj.group(1)
			return protocol

		pattern = "^protocol (\d+)( description .+)?$"
		matchObj = re.match(pattern, elements)
		if(matchObj):
			protocol = matchObj.group(1)
			service_list = []
			pro_dict = {"protocol": protocol, "src_port": const.ANYPORT, "dst_port": const.ANYPORT}
			service_list.append(pro_dict)
			setname = "IP: protocol-num:%s" %(protocol)
			ServiceSetCmdParser().createInternalServices(root_dict, setname, service_list)
			return setname

		pattern = "^protocol (icmp|icmpv6) (icmp-type|icmpv6-type) (\S+)( [to \d+]*)?( description .+)?$"
		matchObj = re.match(pattern, elements)
		if(matchObj):
			protocol = IPConvert().convertService(matchObj.group(1))
			src_port = matchObj.group(3)
			if(None == matchObj.group(4)):
				return IPConvert().convertICMPandICMPv6(matchObj.group(1), src_port)

			dst_port_list = IPConvert().convertPortRange(matchObj.group(4))

			service_list = []
			for dst_port in dst_port_list:
				pro_dict = {"protocol": protocol, "src_port": src_port, "dst_port": dst_port}
				service_list.append(pro_dict)

			dst_port = matchObj.group(4)
			setname = "%s: icmp-type:%s, icmp-code:%s" %(matchObj.group(1).upper(), src_port, dst_port)
			ServiceSetCmdParser().createInternalServices(root_dict, setname, service_list)
			return setname
		
		pattern = "^protocol (tcp|udp|sctp)( source-port ([to \d+]*))?( destination-port ([to \d+]*))?( description .+)?$"
		matchObj = re.match(pattern, elements)
		if(matchObj):
			if(matchObj.group(2)):
				src_port_list = IPConvert().convertPortRange(matchObj.group(3))
			else:
				src_port_list = [const.ANYPORT]
			if(matchObj.group(4)):
				dst_port_list = IPConvert().convertPortRange(matchObj.group(5))
			else:
				dst_port_list = [const.ANYPORT]

			protocol = IPConvert().convertService(matchObj.group(1))
			service_list = []
			for src_port in src_port_list:
				for dst_port in dst_port_list:	
					pro_dict = {"protocol": protocol, "src_port": src_port, "dst_port": dst_port}
					service_list.append(pro_dict)

			src_port = matchObj.group(3) if (matchObj.group(2)) else const.ANYPORT
			dst_port = matchObj.group(5) if (matchObj.group(4)) else const.ANYPORT
			setname = "%s: src-port:%s, dst-port:%s" %(matchObj.group(1).upper(), src_port, dst_port)
			ServiceSetCmdParser().createInternalServices(root_dict, setname , service_list)
			return setname

		pattern = "^%s( description .+)?$" %const.REGEX_NAME
		matchObj = re.match(pattern, elements)
		if(matchObj):
			serviceset = self.ignoreQuotation(matchObj.group(1))
			return serviceset

		return None
	
	def parseCommonCmd(self, cmd, root_dict):
		pattern = "^rule name %s" %const.REGEX_NAME
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			self.rule.cleanAll()
			rule_name = self.ignoreQuotation(matchObj.group(1))
			self.rule.setRuleName(rule_name)
			return const.OK

		matchObj = re.match("^source-zone (.+)", cmd)
		if(matchObj):
			zone = self.parseZone(matchObj.group(1))
			if(None != zone):
				self.rule.appendSrcZone(zone)
			return const.OK

		matchObj = re.match("^destination-zone (.+)", cmd)
		if(matchObj):
			zone = self.parseZone(matchObj.group(1))
			if(None != zone):
				self.rule.appendDstZone(zone)
			return const.OK

		matchObj = re.match("^source-address (.+)", cmd)
		if(matchObj):
			addr = self.parseAddress(matchObj.group(1), root_dict)
			if(None != addr):
				self.rule.appendSrcAddr(addr)
			return const.OK

		matchObj = re.match("^destination-address (.+)", cmd)
		if(matchObj):
			addr = self.parseAddress(matchObj.group(1), root_dict)
			if(None != addr):
				self.rule.appendDstAddr(addr)
			return const.OK		

		matchObj = re.match("^source-address-exclude (.+)", cmd)
		if(matchObj):
			hwDebug("Warn", "doesn't support exclude address yet.")
			return const.OK

		matchObj = re.match("^destination-address-exclude (.+)", cmd)
		if(matchObj):
			hwDebug("Warn", "doesn't support exclude address yet.")
			return const.OK	

		matchObj = re.match("^service (.+)", cmd)
		if(matchObj):
			service = self.parseService(matchObj.group(1), root_dict)
			if(None != service):
				self.rule.appendService(service)
			return const.OK

		pattern = "^time-range %s$" %const.REGEX_NAME
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			timeschedule = self.ignoreQuotation(matchObj.group(1))
			self.rule.setTimeSchedule(timeschedule)
			return const.OK

		matchObj = re.match("^description (.+)", cmd)
		if(matchObj):
			self.rule.setComment(matchObj.group(1))
			return const.OK

		if(cmd == "disable"):
			self.rule.setEnable("disabled")
			return const.OK

		return const.ERR

	def isEnd(self, cmd):
		if(cmd.startswith("rule name ")):
			return 1	
		elif(cmd == "#"):
			return 1
		return 0

class SecPolicyCmdParser(PolicyCmdParser):
	rule = SecPolicyRule()

	defaultrule = SecPolicyRule()
	defaultrule.setAction("deny")

	def createRule(self, root_dict, object):
		root_dict.setdefault("policies", collections.OrderedDict())
		object_dic = root_dict["policies"]

		key = object.getRuleName()
		jsondata = object.getJsonData()
		if(None == key or None == jsondata):
			return
		global rulecount
		rulecount += 1
		object_dic[key] = jsondata
		object_dic[key]["line_number"] = str(rulecount) #TODO:显示成啥
		object_dic[key]["rule_num"] = str(rulecount)
		object.cleanAll()
		return

	def createRuleGroup(self, root_dict, object):
		root_dict.setdefault("rules_groups", collections.OrderedDict())
		object_dic = root_dict["rules_groups"]

		key = object.getName()
		jsondata = object.getJsonData()
		if(None != key and None != jsondata):
			object_dic[key] = jsondata
		return

	def parseDefaultRule(self, cmd):
		if(cmd == "default action permit"):
			self.defaultrule.setAction("allow")
			return const.OK
		elif(cmd == "default action deny"):
			self.defaultrule.setAction("deny")
			return const.OK

		if(cmd == "default policy logging"):
			self.defaultrule.setSyslog("1")
			return const.OK
		return const.ERR

	def addRuleParentGroup(self, root_dict, cmd):
		policy_dict = root_dict.get("policies")
		if(None == policy_dict):
			return

		pattern = "^group name %s from %s to %s" %(const.REGEX_NAME, const.REGEX_NAME, const.REGEX_NAME)
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			groupname = self.ignoreQuotation(matchObj.group(1))
			start_name = self.ignoreQuotation(matchObj.group(2))
			end_name = self.ignoreQuotation(matchObj.group(3))
			if((None == policy_dict.get(start_name)) or (None == policy_dict.get(end_name))):
				hwDebug("Warn", "rule member %s or %s doesn't exist." %(start_name, end_name))
				return
			start_id = int(policy_dict[start_name]["line_number"])
			end_id = int(policy_dict[end_name]["line_number"])
			if(start_id < 1 or start_id > end_id or end_id > len(policy_dict)):
				hwDebug("Warn", "rule member id %s or %s doesn't exist." %(start_id, end_id))
				return
			for temp_id in range(start_id - 1, end_id):
				key = policy_dict.keys()[temp_id]
				policy_dict[key]["rule_grp"] = groupname
		return

	def parseCmd(self, cmd, root_dict):
		if(self.isEnd(cmd)):
			self.createRule(root_dict, self.rule)

		ret = self.parseCommonCmd(cmd, root_dict)
		if(const.OK == ret):
			return const.OK

		if(cmd == "policy logging"):
			self.rule.setSyslog("1")
			return const.OK

		if(cmd == "action permit"):
			self.rule.setAction("allow")
			return const.OK
		elif(cmd == "action deny"):
			self.rule.setAction("deny")
			return const.OK

		pattern = "^parent-group %s" %const.REGEX_NAME
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			group_name = self.ignoreQuotation(matchObj.group(1))
			self.rule.setParentGroup(group_name)
			return const.OK

		pattern = "^group name %s( from %s( to %s)?)?( (disable|enable))?( description (.+))?$" %(const.REGEX_NAME, const.REGEX_NAME, const.REGEX_NAME)
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			group_name = self.ignoreQuotation(matchObj.group(1))
			secgroup = RuleGroup()
			secgroup.setName(group_name)
			if(None != matchObj.group(7)):
				secgroup.setEnable(matchObj.group(7) + "d")
			if(None != matchObj.group(9)):
				secgroup.setComment(matchObj.group(9))
			self.createRuleGroup(root_dict, secgroup)
			self.addRuleParentGroup(root_dict, cmd)
			return const.OK

		#parse default rule
		return self.parseDefaultRule(cmd)

	def isEnd(self, cmd):
		if(cmd.startswith("rule name ")):
			return 1
		elif(cmd.startswith("group name ")):
			return 1
		elif(cmd == "#"):
			return 1
		return 0

class NatPolicyCmdParser(PolicyCmdParser):
	rule = NatPolicyRule()
	defaultrule = NatPolicyRule()

	def createRule(self, root_dict, object):
		root_dict.setdefault("nat_rules", collections.OrderedDict())
		object_dic = root_dict["nat_rules"]

		key = object.getRuleName()
		jsondata = object.getJsonData()
		if(None == key or None == jsondata):
			return
		global natrulecount
		natrulecount += 1	
		object_dic[key] = jsondata
		object_dic[key]["line_number"] = str(natrulecount)
		object_dic[key]["rule_num"] = str(natrulecount)		
		object.cleanAll()
		return

	def parseCmd(self, cmd, root_dict):
		if(self.isEnd(cmd)):
			self.createRule(root_dict, self.rule)

		ret = self.parseCommonCmd(cmd, root_dict)
		if(const.OK == ret):
			return const.OK

		if(cmd == "action no-nat"):
			self.rule.setAction("deny")
			return const.OK
		else:
			self.rule.setAction("allow")
			return const.OK

		return const.ERR

	def isEnd(self, cmd):
		if(cmd.startswith("rule name ")):
			return 1
		elif(cmd == "#"):
			return 1
		return 0
	
class DeviceInfoParser(CmdParser):
	devinfo = DeviceInformation()

	def createDevice(self, root_dict, object):
		root_dict.setdefault("device", collections.OrderedDict())
		root_dict["device"] = object.getJsonData()
		object.cleanAll()

	def parseCmd(self, cmd, root_dict):#TODO how about no version device, sysname with space
		matchObj = re.search("Software.*Version.* [(]?(\S+) (V\d+R\d+C\d+[\dDSPCT]*)", cmd, re.IGNORECASE)
		if(matchObj):
			self.devinfo.setHostName(matchObj.group(1))
			self.devinfo.setVersion(matchObj.group(2))
			self.devinfo.setMajorVersion(matchObj.group(2))
			self.devinfo.setMinorVersion(matchObj.group(2))
			self.createDevice(root_dict, self.devinfo)
			return const.OK

		return const.ERR

routeid = 0
class RouteTableParser(CmdParser):
	route = Route()

	def createRoutingTable(self, root_dict, object):
		root_dict.setdefault("routes", collections.OrderedDict())
		object_dic = root_dict["routes"]
		key = object.getId()
		jsondata = object.getJsonData()
		if(None != key and None != jsondata):
			object_dic[key] = jsondata
		object.cleanAll()

	def parseCmd(self, cmd, root_dict):
		pattern = const.REGEX_IPV4 + "/(\d+) .+ " + const.REGEX_IPV4 + "\s+(.+)"
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			#skip null0 interface
			intf_name = matchObj.group(4)
			if("null" in intf_name.lower()):
				hwDebug("Debug", "ignoring route that is related to interface %s." %(intf_name))
				return const.OK
			global routeid
			routeid += 1
			self.route.setId(routeid)
			dst = matchObj.group(1)
			dst_mask = matchObj.group(2)
			self.route.setRoute(dst)
			self.route.setRouteMask(dst_mask)
			self.route.setGateway(matchObj.group(3))
			self.route.setInterface(matchObj.group(4))

			self.createRoutingTable(root_dict, self.route)
			return const.OK

		return const.ERR

class AddressSetCmdParser(CmdParser):
	addrset = AddressSet()

	def createAddreset(self, root_dict, addrset):
		key = addrset.getName()
		jsondata = addrset.getJsonData()
		if(None == key or None == jsondata):
			return

		if("GROUP" == addrset.getIPType()):
			root_dict.setdefault("hosts_groups", collections.OrderedDict())
			object_dict = root_dict["hosts_groups"]
			object_dict[key] = jsondata
		else:
			root_dict.setdefault("hosts", collections.OrderedDict())
			object_dict = root_dict["hosts"]
			object_dict[key] = jsondata
		addrset.cleanAll()
		return

	def createInternalHosts(self, root_dict, ipv4_str):
		addrset = AddressSet()
		addrset.setName(ipv4_str)
		addrset.appendIPList(ipv4_str)
		addrset.setIPType("INTERNAL")
		self.createAddreset(root_dict, addrset)
		return ipv4_str

	def parseAddrsetCmd(self, cmd, root_dict):
		pattern = "^ip address-set %s type object$" %const.REGEX_NAME
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			self.addrset.cleanAll()
			self.addrset.setIPType("ANY")
			name = self.ignoreQuotation(matchObj.group(1))
			self.addrset.setName(name)
			return const.OK

		pattern = "^ip address-set %s type group$" %const.REGEX_NAME
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			self.addrset.cleanAll()
			self.addrset.setIPType("GROUP")
			name = self.ignoreQuotation(matchObj.group(1))
			self.addrset.setName(name)
			return const.OK

		matchObj = re.match("^description (.+)$", cmd)
		if(matchObj):
			self.addrset.setComment(matchObj.group(1))
			return const.OK

		iptype = self.addrset.getIPType()
		pattern = "^address \d+ %s 0( description .+)?$" %const.REGEX_IPV4
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			ipv4 = matchObj.group(1)
			if( "GROUP" == iptype):
				setname = self.createInternalHosts(root_dict, ipv4)
				self.addrset.appendIPList(setname)
			else:
				self.addrset.appendIPList(ipv4)
			return const.OK

		pattern = "^address \d+ %s mask (\d+)( description .+)?$" %const.REGEX_IPV4
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			ipv4 = matchObj.group(1) + "/" + matchObj.group(2)
			if( "GROUP" == iptype):
				setname = self.createInternalHosts(root_dict, ipv4)
				self.addrset.appendIPList(setname)
			else:
				self.addrset.appendIPList(ipv4)
			return const.OK

		pattern = "^address \d+ %s mask %s( description .+)?$" %(const.REGEX_IPV4, const.REGEX_IPV4)
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			masklen = IPConvert().convertMaskToMaskLen(matchObj.group(2))
			if(0 > masklen):
				return None
			ipv4 = matchObj.group(1) + "/" + str(masklen)
			if( "GROUP" == iptype):
				setname = self.createInternalHosts(root_dict, ipv4)
				self.addrset.appendIPList(setname)
			else:
				self.addrset.appendIPList(ipv4)
			return const.OK

		pattern = "^address \d+ %s %s( description .+)?$" %(const.REGEX_IPV4, const.REGEX_IPV4)
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			mask = IPConvert().convertWildcardMaskToMask(matchObj.group(2))
			masklen = IPConvert().convertMaskToMaskLen(mask)
			if(0 > masklen):
				return const.OK
			ipv4 = matchObj.group(1) + "/" + str(masklen)
			if( "GROUP" == iptype):
				setname = self.createInternalHosts(root_dict, ipv4)
				self.addrset.appendIPList(setname)
			else:
				self.addrset.appendIPList(ipv4)
			return const.OK
		
		pattern = "^address \d+ range %s %s( description .+)?$" %(const.REGEX_IPV4, const.REGEX_IPV4)
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			ipv4_range = matchObj.group(1) + "-" + matchObj.group(2)
			if( "GROUP" == iptype):
				setname = self.createInternalHosts(root_dict, ipv4_range)
				self.addrset.appendIPList(setname)
			else:
				self.addrset.appendIPList(ipv4_range)
			return const.OK
		
		pattern = "^address \d+ address-set %s( description .+)?$" %const.REGEX_NAME
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			addrset_name = self.ignoreQuotation(matchObj.group(1))
			self.addrset.appendIPList(addrset_name)
			return const.OK

		return const.ERR

	def parseGeoCmd(self, cmd, root_dict):
		pattern = "^geo-location user-defined %s$" %const.REGEX_NAME
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			self.addrset.cleanAll()
			self.addrset.setIPType("ANY")
			name = const.GEO_PREFIX + self.ignoreQuotation(matchObj.group(1))
			self.addrset.setName(name)
			return const.OK

		pattern = "^geo-location-set %s$" %const.REGEX_NAME
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			self.addrset.setIPType("GROUP")
			name = const.GEOSET_PREFIX + self.ignoreQuotation(matchObj.group(1))
			self.addrset.setName(name)
			return const.OK

		pattern = "^add geo-location %s$" %(const.REGEX_NAME)
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			geoname = const.GEO_PREFIX + matchObj.group(1)
			self.addrset.appendIPList(geoname)
			return const.OK

		pattern = "^add geo-location-set %s$" %(const.REGEX_NAME)
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			geoname = const.GEOSET_PREFIX + matchObj.group(1)
			self.addrset.appendIPList(geoname)
			return const.OK

		pattern = "^add address range %s %s$" %(const.REGEX_IPV4, const.REGEX_IPV4)
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			ipv4_range = matchObj.group(1) + "-" + matchObj.group(2)
			self.addrset.appendIPList(ipv4_range)
			return const.OK

		pattern = "^add address %s mask (\d+)$" %const.REGEX_IPV4
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			ipv4 = matchObj.group(1) + "/" + matchObj.group(2)
			self.addrset.appendIPList(ipv4)
			return const.OK

		pattern = "^add address %s mask %s$" %(const.REGEX_IPV4, const.REGEX_IPV4)
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			masklen = IPConvert().convertMaskToMaskLen(matchObj.group(2))
			if(0 > masklen):
				return None
			ipv4 = matchObj.group(1) + "/" + str(masklen)
			self.addrset.appendIPList(ipv4)
			return const.OK

		return const.ERR

	def parseCmd(self, cmd, root_dict):
		if(self.isEnd(cmd)):
			self.createAddreset(root_dict, self.addrset)

		ret = self.parseAddrsetCmd(cmd, root_dict)
		if(const.OK == ret):
			return const.OK

		return self.parseGeoCmd(cmd, root_dict)

	def isEnd(self, cmd):
		if(cmd.startswith("ip address-set ")):
			return 1
		elif(cmd.startswith("geo-location ")):
			return 1
		elif(cmd.startswith("geo-location-set ")):
			return 1
		elif(cmd == "#"):
			return 1
		return 0

class ServiceSetCmdParser(CmdParser):
	serviceset = ServiceSet()

	def createServiceset(self, root_dict, serviceset):
		key = serviceset.getName()
		jsondata = serviceset.getJsonData()
		if(None == key or None == jsondata):
			return

		if("GROUP" == serviceset.getServiceType()):
			root_dict.setdefault("services_groups", collections.OrderedDict())
			object_dict = root_dict["services_groups"]
			object_dict[key] = jsondata
		else:
			root_dict.setdefault("services", collections.OrderedDict())
			object_dict = root_dict["services"]
			object_dict[key] = jsondata
		serviceset.cleanAll()
		return

	def createInternalServices(self, root_dict, setname, service):
		serviceset = ServiceSet()
		serviceset.setName(setname)
		serviceset.setServiceList(service)
		serviceset.setServiceType("INTERNAL")
		self.createServiceset(root_dict, serviceset)
		return setname

	def parseCmd(self, cmd, root_dict):
		if(self.isEnd(cmd)):
			self.createServiceset(root_dict, self.serviceset)

		pattern = "^ip service-set %s type object$" %const.REGEX_NAME
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			self.serviceset.cleanAll()
			self.serviceset.setServiceType("ANY")
			name = self.ignoreQuotation(matchObj.group(1))
			self.serviceset.setName(name)
			return const.OK

		pattern = "^ip service-set %s type group$" %const.REGEX_NAME
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			self.serviceset.cleanAll()
			self.serviceset.setServiceType("GROUP")
			name = self.ignoreQuotation(matchObj.group(1))
			self.serviceset.setName(name)
			return const.OK

		matchObj = re.match("^description (.+)$", cmd)
		if(matchObj):
			self.serviceset.setComment(matchObj.group(1))
			return const.OK

		pattern = "^service \d+ protocol (\d+|icmp|icmpv6|sctp|tcp|udp)( description .+)?$"
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			protocol = IPConvert().convertService(matchObj.group(1))
			pro_dict = {"protocol": protocol, "src_port": const.ANYPORT, "dst_port": const.ANYPORT}
			self.serviceset.appendServiceList(pro_dict)
			return const.OK

		pattern = "^service \d+ protocol (icmp|icmpv6) (icmp-type|icmpv6-type) (\S+)( [to \d+]*)?( description .+)?$"
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			protocol = IPConvert().convertService(matchObj.group(1))
			src_port = matchObj.group(3)
			if(None == matchObj.group(4)):
				key = IPConvert().convertICMPandICMPv6(matchObj.group(1), src_port)
				src_port, dst_port = self.findPredefinedService(key)
				if(None == src_port or None == dst_port):
					hwDebug("Warn", "ignoring service item %s." %(src_port))
					return const.ERR

				protocol = IPConvert().convertService(matchObj.group(1))
				pro_dict = {"protocol": protocol, "src_port": src_port, "dst_port": dst_port}
				self.serviceset.appendServiceList(pro_dict)
				return const.OK

			dst_port_list = IPConvert().convertPortRange(matchObj.group(4))
			for dst_port in dst_port_list:
				pro_dict = {"protocol": protocol, "src_port": src_port, "dst_port": dst_port}
				self.serviceset.appendServiceList(pro_dict)
			return const.OK

		pattern = "^service \d+ protocol (tcp|udp|sctp)( source-port ([to \d+]*))?( destination-port ([to \d+]*))?( description .+)?$"
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			protocol = IPConvert().convertService(matchObj.group(1))
			if(matchObj.group(2)):
				src_port_list = IPConvert().convertPortRange(matchObj.group(3))
			else:
				src_port_list = [const.ANYPORT]
			if(matchObj.group(4)):
				dst_port_list = IPConvert().convertPortRange(matchObj.group(5))
			else:
				dst_port_list = [const.ANYPORT]
			
			for src_port in src_port_list:
				for dst_port in dst_port_list:	
					pro_dict = {"protocol": protocol, "src_port": src_port, "dst_port": dst_port}
					self.serviceset.appendServiceList(pro_dict)
			return const.OK

		pattern = "^service \d+ service-set %s( description .+)?$" %const.REGEX_NAME
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			service_name = self.ignoreQuotation(matchObj.group(1))
			self.serviceset.appendServiceList(service_name)
			return const.OK

		return const.ERR

	def isEnd(self, cmd):
		if(cmd.startswith("ip service-set ")):
			return 1
		elif(cmd == "#"):
			return 1
		return 0

	def createPredefinedService(self, root_dict):
		pro_tuple = predefined.PreDefinedData().predefinedservice + predefined.PreDefinedData().predefinedicmptype + predefined.PreDefinedData().predefinedicmpv6type

		root_dict.setdefault("services", collections.OrderedDict())
		object_dict = root_dict["services"]

		number = len(pro_tuple)
		i = 0
		for i in range(1, number):
			pre_serviceset = ServiceSet()
			key = pro_tuple[i][0]
			pre_serviceset.setName(key)
			pre_serviceset.setServiceType("PREDEFINED")
			pre_serviceset.setComment(pro_tuple[i][4])
			pro_dict = {"protocol":pro_tuple[i][1], "src_port":pro_tuple[i][2], "dst_port":pro_tuple[i][3]}
			if(None != object_dict.get(key)):
				pre_serviceset.setServiceList(object_dict[key]["service_definitions"])
			pre_serviceset.appendServiceList(pro_dict)
			object_dict[key] = pre_serviceset.getJsonData()

		return

	def findPredefinedService(self, name):
		pro_tuple = predefined.PreDefinedData().predefinedicmptype + predefined.PreDefinedData().predefinedicmpv6type
		number = len(pro_tuple)
		i = 0
		for i in range(0, number):
			key = pro_tuple[i][0]
			if(key == name):
				return pro_tuple[i][2], pro_tuple[i][3]
		return None, None

#protocol status
class InterfaceCmdParser(CmdParser):
	interface = Interface()

	def createInterface(self, root_dict, object):
		key = object.getName()
		jsondata = object.getJsonData()
		if(None == key or None == jsondata):
			return
		root_dict.setdefault("interfaces", collections.OrderedDict())
		object_dict = root_dict["interfaces"]
		object_dict[key] = jsondata
		object.cleanAll()
		return

	def setDefaultValue(self, root_dict):
		intf_dict = root_dict.get("interfaces")
		if(None != intf_dict):
			for temp_intf in intf_dict.keys():
				if(None == intf_dict[temp_intf]["enable"]):
					intf_dict[temp_intf]["enable"] = "enabled"
		return
	
	def parseCmd(self, cmd, root_dict):
		if(self.isEnd(cmd)):
			self.createInterface(root_dict, self.interface)

		pattern = "^interface %s$" %const.REGEX_NAME
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			self.interface.cleanAll()
			intf_name = self.ignoreQuotation(matchObj.group(1))
			#skip null0 interface
			if("null" in intf_name.lower()):
				hwDebug("Debug", "ignoring interface %s." %(intf_name))
				return const.OK
			self.interface.setName(intf_name)
			return const.OK

		pattern = "^ip address %s %s( sub)?$" %(const.REGEX_IPV4, const.REGEX_IPV4)
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			masklen = IPConvert().convertMaskToMaskLen(matchObj.group(2))
			if(0 > masklen):
				return const.OK
			ipv4 = matchObj.group(1) + "/" + str(masklen)
			self.interface.appendIPList(ipv4)
			return const.OK

		if(cmd == "portswitch"):
			self.interface.appendIPList("layer2")
			return const.OK

		if(cmd == "shutdown"):
			self.interface.setEnable("disabled")
			return const.OK
		elif(cmd == "undo shutdown"):
			self.interface.setEnable("enabled")
			return const.OK

		pattern = "^alias (.+)$"
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			self.interface.setComment(matchObj.group(1))
			return const.OK

		self.interface.setZone("")

		return const.ERR

	def isEnd(self, cmd):
		if(cmd.startswith("interface ")):
			return 1	
		elif(cmd == "#"):
			return 1
		return 0

class ZoneCmdParser(CmdParser):
	zone = Zone()

	def createZone(self, root_dict, object):
		key = object.getName()
		jsondata = object.getJsonData()
		if(None == key or None == jsondata):
			return
		root_dict.setdefault("zones", collections.OrderedDict())
		object_dict = root_dict["zones"]
		object_dict[key] = jsondata
		object.cleanAll()
		return
		
	def parseCmd(self, cmd, root_dict):
		if(self.isEnd(cmd)):
			self.createZone(root_dict, self.zone)

		pattern = "^firewall zone (local|trust|untrust|dmz)$"
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			self.zone.cleanAll()
			self.zone.setName(matchObj.group(1))
			return const.OK

		pattern = "^firewall zone name %s id \d+$" %const.REGEX_NAME
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			zonename = self.ignoreQuotation(matchObj.group(1))
			self.zone.setName(zonename)
			return const.OK

		matchObj = re.match("^description (.+)$", cmd)
		if(matchObj):
			self.zone.setComment(matchObj.group(1))
			return const.OK

		pattern = "^add interface %s$" %const.REGEX_NAME
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			interface_name = self.ignoreQuotation(matchObj.group(1))
			self.zone.appendInterface(interface_name)
			self.addZoneToInterface(root_dict, interface_name, self.zone.getName())
			return const.OK

		return const.ERR

	def addZoneToInterface(self, root_dict, interface, zonename):
		object_dict = root_dict.get("interfaces")
		if(None == object_dict):
			return
		object_dict = object_dict.get(interface)
		if(None == object_dict):
			hwDebug("Warn", "doesn't find interface %s for zone %s" %(interface, zonename))
			return
		object_dict["zone"] = zonename
		
	def isEnd(self, cmd):
		if(cmd.startswith("firewall zone ")):
			return 1	
		elif(cmd == "#"):
			return 1
		return 0

class ScheduleCmdParser(CmdParser):
	timeschedule = TimeSchedule()

	def createTimeSchedule(self, root_dict, object):
		key = object.getName()
		jsondata = object.getJsonData()
		if(None == key or None == jsondata):
			return
		root_dict.setdefault("schedules", collections.OrderedDict())
		object_dict = root_dict["schedules"]
		object_dict[key] = jsondata
		object.cleanAll()
		return

	def convertTime(self, date_str, endtimeflag):
		date = datetime.datetime.strptime(date_str, "%H:%M:%S %Y/%m/%d")
		hour = date.hour
		minute = date.minute
		if(endtimeflag and date.second > 30):
			minute = minute + 1
			if(60 == minute):
				minute = 0
				hour = hour + 1

		new_date = "%02d%02d%04d %02d%02d" %(date.day, date.month, date.year, hour, minute)
		return new_date;

	def parseCmd(self, cmd, root_dict):
		if(self.isEnd(cmd)):
			self.createTimeSchedule(root_dict, self.timeschedule)

		pattern = "^time-range %s$" %const.REGEX_NAME
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			self.timeschedule.cleanAll()
			name = self.ignoreQuotation(matchObj.group(1))
			self.timeschedule.setName(name)
			return const.OK

		#TODO: algosec不支持秒
		pattern = "^absolute-range %s to %s$" %(const.REGEX_DATE, const.REGEX_DATE)
		matchObj = re.match(pattern, cmd)
		if(matchObj):
			start_date = self.convertTime(matchObj.group(1), 0)
			end_date = self.convertTime(matchObj.group(2), 1)

			self.timeschedule.setStartDate(start_date)
			self.timeschedule.setEndDate(end_date)
			return const.OK

		matchObj = re.match("^period-range .+$", cmd)
		if(matchObj):
			#TODO algosec不支持周期时间
			hwDebug("Warn", "doesn't support period-time yet.")
			return const.OK

		return const.ERR
		
	def isEnd(self, cmd):
		if(cmd.startswith("time-range ")):
			return 1	
		elif(cmd == "#"):
			return 1
		return 0

class ModuleParser():
	cmdtype = const.NONE
	vsys_end = 0
	module_start = 0;
	
	def setCmdType(self, cmdtype):
		self.cmdtype = cmdtype
	def getCmdType(self):
		return self.cmdtype

	def isCfgEnd(self, line):
		if(line == "return"):#only parse one virtual system
			return 1
		return 0

	def parseModuleBegin(self, line):
		#identify cmd type
		matchObj = re.match("^===\s+(.+)\s+===$", line)
		if(matchObj):
			cmd = matchObj.group(1)
			hwDebug("Debug", cmd)
			if(cmd == "display version"):
				self.setCmdType(const.CMD_VERSION)
				return
			elif(cmd == "display current-configuration"):
				self.setCmdType(const.CMD_CONFIG)
			elif(cmd == "display ip routing-table"):
				self.setCmdType(const.CMD_ROUTE)
				return

		#identify current-configuration type
		if(0 != (const.CMD_CONFIG & self.getCmdType())):
			if(line == "#"):
				self.module_start = 1
				return

			if(1 == self.module_start):
				self.module_start = 0
				if(line == "security-policy"):
					self.setCmdType(const.CMD_SEC_POLICY)
				#elif(line == "nat-policy"):
				#	self.setCmdType(const.CMD_NAT_POLICY)
				elif(line.startswith("ip address-set ")):
					self.setCmdType(const.CMD_ADDRSET)
				elif(line.startswith("geo-location ")):
					self.setCmdType(const.CMD_ADDRSET)
				elif(line.startswith("geo-location-set ")):
					self.setCmdType(const.CMD_ADDRSET)
				elif(line.startswith("ip service-set ")):
					self.setCmdType(const.CMD_SERVICE)
				elif(line.startswith("interface ")):
					self.setCmdType(const.CMD_INTERFACE)
				elif(line.startswith("firewall zone ")):
					self.setCmdType(const.CMD_ZONE)
				elif(line.startswith("time-range ")):
					self.setCmdType(const.CMD_SCHEDULE)
				else:
					self.setCmdType(const.CMD_CONFIG)

	def parseModuleEnd(self, line, root_dict):
		if(self.isCfgEnd(line) and (self.vsys_end == 0)):
			self.vsys_end = 1
			self.setCmdType(const.NONE)
			ServiceSetCmdParser().createPredefinedService(root_dict)

			secparser = SecPolicyCmdParser()
			secparser.defaultrule.setRuleName("default")
			secparser.defaultrule.setComment("This is the default rule")
			secparser.createRule(root_dict, secparser.defaultrule)		

			InterfaceCmdParser().setDefaultValue(root_dict)
	
	def parseModule(self, line, root_dict):
		self.parseModuleBegin(line)
		parser = CmdParser()
		
		cmd_type = self.getCmdType()
		#parse version
		if(const.CMD_VERSION == cmd_type):
			parser = DeviceInfoParser()
	
		#parse ip-routing table
		if(const.CMD_ROUTE == cmd_type):
			parser = RouteTableParser()

		#parse current configuration
		if(const.CMD_SEC_POLICY == cmd_type):
			parser = SecPolicyCmdParser()
		elif(const.CMD_NAT_POLICY == cmd_type):
			parser = NatPolicyCmdParser()
		elif(const.CMD_ADDRSET == cmd_type):
			parser = AddressSetCmdParser()
		elif(const.CMD_SERVICE == cmd_type):
			parser = ServiceSetCmdParser()
		elif(const.CMD_INTERFACE == cmd_type):
			parser = InterfaceCmdParser()
		elif(const.CMD_ZONE == cmd_type):
			parser = ZoneCmdParser()
		elif(const.CMD_SCHEDULE == cmd_type):
			parser = ScheduleCmdParser()
		parser.parseCmd(line, root_dict)

		self.parseModuleEnd(line, root_dict)
		return
		
class MyUtil():
	def stripSpace(self, origincmd):
		newcmd = origincmd
		if(newcmd.startswith(const.TELNETSTR)):
			newcmd = newcmd[len(const.TELNETSTR):-1]
		newcmd = newcmd.strip(' \n')
		return newcmd
	
	def getFileLength(self, filename):
		if(None == filename):
			return 0
		count = -1
		for count, line in enumerate(open(filename, 'rU')):
			pass
		count += 1
		return count

	def searchFileBySuffix(self, directory, suffix):
		list_dirs = os.walk(directory) 
		for root, dirs, files in list_dirs: 
			for name in files:
				if(name.endswith(suffix)):
					return name
		return None

def hwDebug(level, debuginfo):
	newdebuginfo = "\n[hw][%s]: %s"  %(level, debuginfo)
	sys.stderr.write(newdebuginfo)
	return

#TODO: catch exception
if __name__ == '__main__':

	parser = ModuleParser()
	myUtil = MyUtil()

	try:
		root_dict = collections.OrderedDict();
		root_dict["version"] = "1.0"
		root_dict["config_type"] = "ZONE_BASED"
		root_dict["device"] = collections.OrderedDict()	
		root_dict["hosts"] = collections.OrderedDict()#must have hosts.

		cfgfilename = myUtil.searchFileBySuffix(".", ".huawei")
		if(None == cfgfilename):
			hwDebug("Error", "can't find configuration file with suffix \".huawei\".")
			raise IOError

		cfgfile = open(cfgfilename, "r")
		length = myUtil.getFileLength(cfgfilename)

		i = 0
		while(i < length):
			i += 1
			eachline = cfgfile.next().decode("utf-8")
			newline = myUtil.stripSpace(eachline)
			parser.parseModule(newline, root_dict)
	
		json_data = json.dumps(root_dict, ensure_ascii = False, indent = 4, separators = (',', ':'))
		hwDebug("Debug:", json_data.encode('utf-8'))
		jsonfile = open(const.JSON_FILENAME, "w+")
		jsonfile.write(json_data.encode('utf-8'))
		jsonfile.close()

		cfgfile.close()
	except IOError:
		hwDebug("Error", "can't find file.")
	else:
		hwDebug("Debug", "parse OK!")

