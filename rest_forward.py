
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
