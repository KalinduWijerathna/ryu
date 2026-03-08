from ryu.ofproto import ether
from ryu.lib.packet import in_proto

from . import protocol_map


class ACLManager(object):

    def __init__(self, intent_store, logger):
        self.intent_store = intent_store
        self.logger = logger

    def _resolve_protocol(self, proto_name):
        key = proto_name.lower()
        if key in protocol_map.PROTOCOL_MAP:
            return protocol_map.PROTOCOL_MAP[key]
        return None, None

    def _get_base_priority(self, user_role, action):
        role = user_role.lower() if user_role else 'user'
        base = protocol_map.ACL_ROLE_PRIORITY.get(role, 20000)
        if action.lower() == 'deny':
            base += protocol_map.ACL_DENY_OFFSET
        return base

    def apply_acl_rules(self, datapaths, acl_config, intent_id, user_role):
        cookie = self.intent_store.get_cookie(intent_id)
        if cookie is None:
            self.logger.error('No cookie found for intent %s', intent_id)
            return

        rules = acl_config.get('rules', [])

        # Handle flat ACL format (no 'rules' key, fields directly in acl_config)
        if not rules and acl_config.get('action'):
            rules = [acl_config]

        if not rules:
            self.logger.info('No ACL rules to apply for intent %s', intent_id)
            return

        for rule in rules:
            action = rule.get('action', 'deny')
            src_ip = rule.get('source_ip')
            dst_ip = rule.get('destination_ip')
            src_port = rule.get('source_port')
            dst_port = rule.get('destination_port')
            protocols = rule.get('protocols', [])

            # Also handle singular 'protocol' field
            if not protocols and rule.get('protocol'):
                proto_val = rule['protocol']
                if isinstance(proto_val, list):
                    protocols = proto_val
                else:
                    protocols = [proto_val]

            if not protocols:
                protocols = ['tcp']

            for proto_name in protocols:
                ip_proto, default_port = self._resolve_protocol(proto_name)
                if ip_proto is None:
                    self.logger.warning('Unknown protocol: %s', proto_name)
                    continue

                # Normalize ports to list
                dst_ports = self._normalize_ports(dst_port, default_port)
                src_ports = self._normalize_ports(src_port, None)

                for dp in dst_ports or [None]:
                    for sp in src_ports or [None]:
                        self._install_acl_flow(
                            datapaths, cookie, user_role, action,
                            ip_proto, src_ip, dst_ip, sp, dp
                        )

        self.logger.info('ACL rules applied for intent %s', intent_id)

    def _normalize_ports(self, port_value, default_port):
        if port_value is None:
            if default_port is not None:
                return [default_port]
            return None

        if isinstance(port_value, list):
            return [int(p) for p in port_value]
        if isinstance(port_value, str):
            # Handle "[80,81,82]" format
            port_value = port_value.strip('[]')
            if ',' in port_value:
                return [int(p.strip()) for p in port_value.split(',')]
            return [int(port_value)]
        return [int(port_value)]

    def _install_acl_flow(self, datapaths, cookie, user_role, action,
                          ip_proto, src_ip, dst_ip, src_port, dst_port):
        priority = self._get_base_priority(user_role, action)

        for dpid, datapath in datapaths.items():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            match_fields = {'eth_type': ether.ETH_TYPE_IP, 'ip_proto': ip_proto}

            if src_ip:
                match_fields['ipv4_src'] = src_ip
            if dst_ip:
                match_fields['ipv4_dst'] = dst_ip
            if src_port is not None:
                if ip_proto == in_proto.IPPROTO_TCP:
                    match_fields['tcp_src'] = src_port
                elif ip_proto == in_proto.IPPROTO_UDP:
                    match_fields['udp_src'] = src_port
            if dst_port is not None:
                if ip_proto == in_proto.IPPROTO_TCP:
                    match_fields['tcp_dst'] = dst_port
                elif ip_proto == in_proto.IPPROTO_UDP:
                    match_fields['udp_dst'] = dst_port

            match = parser.OFPMatch(**match_fields)

            if action.lower() == 'allow':
                actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            else:
                actions = []  # drop

            inst = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]

            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=inst,
                cookie=cookie,
                cookie_mask=0xFFFFFFFFFFFFFFFF,
            )
            datapath.send_msg(mod)
            self.logger.debug(
                'ACL flow installed on dpid=%016x action=%s proto=%d',
                dpid, action, ip_proto)

    def remove_acl_rules(self, datapaths, intent_id):
        cookie = self.intent_store.get_cookie(intent_id)
        if cookie is None:
            return

        for dpid, datapath in datapaths.items():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            match = parser.OFPMatch()
            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match,
                cookie=cookie,
                cookie_mask=0xFFFFFFFFFFFFFFFF,
            )
            datapath.send_msg(mod)
            self.logger.debug(
                'ACL flows deleted on dpid=%016x for intent %s', dpid, intent_id)
