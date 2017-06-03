
import logging
import json
import re

from ryu.app import conf_switch_key as cs_key
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import route
from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.controller import conf_switch
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.exception import OFPUnknownVersion
from ryu.lib import dpid as dpid_lib
from ryu.lib import mac
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3
from ryu.lib.ovs import bridge
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto import ether
from ryu.ofproto import inet

# About forward rules:
# get rules of all port forwards 
# * for no vlan
# GET /forward/rules/{switch-id}
# * for specific vlan group
# GET /forward/rules/{switch-id}/{vlan-id}
# set a rule to the specific switch
# * for no vlan
# POST /forward/rules/{switch-id}
# * for specific vlan group
# POST /forward/rules/{switch-id}/{vlan-id}
# delete a rule of port forward of the specific switch from ruleID
# * for no vlan
# DELETE /forward/rules/{switch-id}
# * for specific vlan group
# DELETE /forward/rules/{switch-id}/{vlan-id}
# request body format:
# {"<field>":"<value>"}
# "rule_id" : "<int>" or "all"

SWITCHID_PATTERN = dpid_lib.DPID_PATTERN + r'|all'
VLANID_PATTERN = r'[0-9]{1,4}|all'

QOS_TABLE_ID = 0

REST_ALL = 'all'
REST_SWITCHID = 'switch_id'
REST_COMMAND_RESULT = 'command_result'
REST_PRIORITY = 'priority'
REST_VLANID = 'vlan_id'
REST_PORT_NAME = 'port_name'
REST_FORWARD = 'forward'
REST_FORWARD_ID = 'forward_id'
REST_COOKIE = 'cookie'

REST_MATCH = 'match'
REST_IN_PORT = 'in_port'
REST_SRC_MAC = 'dl_src'
REST_DST_MAC = 'dl_dst'
REST_DL_TYPE = 'dl_type'
REST_DL_TYPE_ARP = 'ARP'
REST_DL_TYPE_IPV4 = 'IPv4'
REST_DL_TYPE_IPV6 = 'IPv6'
REST_DL_VLAN = 'dl_vlan'
REST_SRC_IP = 'nw_src'
REST_DST_IP = 'nw_dst'
REST_SRC_IPV6 = 'ipv6_src'
REST_DST_IPV6 = 'ipv6_dst'
REST_NW_PROTO = 'nw_proto'
REST_NW_PROTO_TCP = 'TCP'
REST_NW_PROTO_UDP = 'UDP'
REST_NW_PROTO_ICMP = 'ICMP'
REST_NW_PROTO_ICMPV6 = 'ICMPv6'
REST_TCP_SRC = 'tcp_src'
REST_TCP_DST = 'tcp_dst'
REST_DSCP = 'ip_dscp'

REST_ACTION = 'actions'
REST_ACTION_TCP_DST = 'tcp_dst'
REST_ACTION_TCP_SRC = 'tcp_src'
REST_OUTPUT = 'OUTPUT'

REST_METER_ID = 'meter_id'
REST_METER_BURST_SIZE = 'burst_size'
REST_METER_RATE = 'rate'
REST_METER_PREC_LEVEL = 'prec_level'
REST_METER_BANDS = 'bands'
REST_METER_ACTION_DROP = 'drop'
REST_METER_ACTION_REMARK = 'remark'

DEFAULT_FLOW_PRIORITY = 0
QOS_PRIORITY_MAX = ofproto_v1_3_parser.UINT16_MAX - 1
QOS_PRIORITY_MIN = 1

VLANID_NONE = 0
VLANID_MIN = 2
VLANID_MAX = 4094
COOKIE_SHIFT_VLANID = 32

BASE_URL = '/forward'
REQUIREMENTS = {'switchid': SWITCHID_PATTERN,
                'vlanid': VLANID_PATTERN}

LOG = logging.getLogger(__name__)






    def _set_forward(self, cookie, rest, waiters, vlan_id):
        match_value=rest[REST_MATCH]
        if vlan_id:
            match_value[REST_DL_VLAN] = vlan_id

        priority = int(rest.get(REST_PRIORITY, QOS_PRIORITY_MIN))
        if (QOS_PRIORITY_MAX < priority):
            raise ValueError('Invalid priority value. Set [%d-%d]'
                             % (QOS_PRIORITY_MIN, QOS_PRIORITY_MAX))

        match = Match.to_openflow(match_value)
        actions = []
        action = rest.get(REST_ACTION, None)
        in_port = match.get(REST_IN_PORT, None)
        
        for a in action:
            output = a.get('OUTPUT')
            if a.get(REST_ACTION_TCP_DST):
                actions.append({'type': 'SET_FIELD',
                                'field': REST_TCP_DST,
                                'value': int(a.get(REST_ACTION_TCP_DST))
                                'port': int(in_port)})
                actions.append({'type': 'OUTPUT',
                                'value': int(output)})
            if a.get(REST_ACTION_TCP_SRC):
                actions.append({'type': 'SET_FIELD',
                                'field': REST_TCP_SRC,
                                'value': int(a.get(REST_ACTION_TCP_SRC))
                                'port': int(output)})
                actions.append({'type': 'OUTPUT',
                                'value': int(output)})
        actions.append({'type': 'GOTO_TABLE',
                        'table_id': QOS_TABLE_ID + 1})
        flow = self._to_of_flow(cookie=cookie, priority=priority,
                                match=match, actions=actions)  
        
        


