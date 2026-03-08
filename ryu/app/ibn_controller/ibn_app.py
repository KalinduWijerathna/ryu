from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.app.wsgi import WSGIApplication

from .intent_store import IntentStore
from .acl_manager import ACLManager
from .qos_manager import QoSManager
from .monitor_manager import MonitorManager
from .rest_controller import IBNRestController

ibn_instance_name = 'ibn_app'


class IBNController(simple_switch_13.SimpleSwitch13):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(IBNController, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.intent_store = IntentStore()
        self.acl_manager = ACLManager(self.intent_store, self.logger)
        self.qos_manager = QoSManager(self.intent_store, self.logger)
        self.monitor_manager = MonitorManager(self.logger)

        wsgi = kwargs['wsgi']
        wsgi.register(IBNRestController, {ibn_instance_name: self})

        self.monitor_manager.start(self.datapaths)
        self.logger.info('IBN Controller initialized')

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        super(IBNController, self).switch_features_handler(ev)
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath

        # Install ARP pass-through at high priority
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=65534,
            match=match,
            instructions=inst,
        )
        datapath.send_msg(mod)
        self.logger.info('Switch connected: dpid=%016x', datapath.id)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('Datapath registered: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('Datapath unregistered: %016x', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        self.monitor_manager.handle_flow_stats(ev)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        self.monitor_manager.handle_port_stats(ev)

    def apply_intent(self, intent_config):
        config = intent_config.get('config', intent_config)
        intent_id = config.get('intent_id')
        user_role = config.get('user_role', 'user')

        if not intent_id:
            return {'error': 'Missing intent_id'}

        # Store the intent
        stored = self.intent_store.add_intent(intent_id, config)

        # Apply ACL rules
        acl_config = config.get('ACL', {})
        if acl_config:
            self.acl_manager.apply_acl_rules(
                self.datapaths, acl_config, intent_id, user_role)

        # Apply QoS rules
        qos_config = config.get('QOS', config.get('QoS', {}))
        if qos_config and qos_config.get('protocol'):
            self.qos_manager.apply_qos(
                self.datapaths, qos_config, intent_id, user_role)

        self.logger.info('Intent applied: %s', intent_id)
        return {
            'intent_id': intent_id,
            'status': 'applied',
            'cookie': stored['cookie'],
            'switches': len(self.datapaths),
        }

    def delete_intent(self, intent_id):
        intent = self.intent_store.get_intent(intent_id)
        if intent is None:
            return {'error': 'Intent not found: %s' % intent_id}

        config = intent['config']

        # Remove ACL rules
        acl_config = config.get('ACL', {})
        if acl_config:
            self.acl_manager.remove_acl_rules(self.datapaths, intent_id)

        # Remove QoS rules and meters
        qos_config = config.get('QOS', config.get('QoS', {}))
        if qos_config and qos_config.get('protocol'):
            self.qos_manager.remove_qos(self.datapaths, intent_id)

        self.intent_store.remove_intent(intent_id)
        self.logger.info('Intent deleted: %s', intent_id)
        return {'intent_id': intent_id, 'status': 'deleted'}
