from ryu.ofproto import ether
from ryu.lib.packet import in_proto

from . import protocol_map


class QoSManager(object):

    def __init__(self, intent_store, logger):
        self.intent_store = intent_store
        self.logger = logger

    def _parse_bandwidth(self, bw_str):
        """Parse bandwidth string like '100Mbps', '1G', '9.5G' to kbps."""
        if bw_str is None:
            return None
        bw_str = str(bw_str).strip().upper()
        if bw_str.endswith('GBPS') or bw_str.endswith('G'):
            num = bw_str.replace('GBPS', '').replace('G', '')
            return int(float(num) * 1000000)
        if bw_str.endswith('MBPS') or bw_str.endswith('M'):
            num = bw_str.replace('MBPS', '').replace('M', '')
            return int(float(num) * 1000)
        if bw_str.endswith('KBPS') or bw_str.endswith('K'):
            num = bw_str.replace('KBPS', '').replace('K', '')
            return int(float(num))
        # Assume Mbps if no unit
        return int(float(bw_str) * 1000)

    def apply_qos(self, datapaths, qos_config, intent_id, user_role):
        cookie = self.intent_store.get_cookie(intent_id)
        if cookie is None:
            self.logger.error('No cookie found for intent %s', intent_id)
            return

        proto_key = qos_config.get('protocol', '').lower()
        priority_level = qos_config.get('priority', 'medium').lower()

        # Look up QoS profile
        profile = protocol_map.QOS_PROFILES.get(proto_key)
        if profile is None:
            self.logger.warning('No QoS profile for protocol: %s', proto_key)
            return

        dscp_value = profile['dscp']

        # Determine bandwidth: use intent-specified or fall back to profile default
        bandwidth_kbps = self._parse_bandwidth(qos_config.get('bandwidth'))
        if bandwidth_kbps is None:
            bandwidth_kbps = profile['bandwidth']

        flow_priority = protocol_map.QOS_PRIORITY_MAP.get(priority_level, 12000)

        # Resolve IP protocol from profile
        ip_proto_entry = protocol_map.PROTOCOL_MAP.get(proto_key)
        if ip_proto_entry is None:
            self.logger.warning('No protocol mapping for: %s', proto_key)
            return
        ip_proto, default_port = ip_proto_entry

        for dpid, datapath in datapaths.items():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            # Allocate a meter ID for this datapath
            meter_id = self.intent_store.allocate_meter_id()
            self.intent_store.add_meter_id(intent_id, meter_id)

            # Install meter with drop band
            bands = [parser.OFPMeterBandDrop(
                rate=bandwidth_kbps, burst_size=0)]
            meter_mod = parser.OFPMeterMod(
                datapath=datapath,
                command=ofproto.OFPMC_ADD,
                flags=ofproto.OFPMF_KBPS,
                meter_id=meter_id,
                bands=bands,
            )
            datapath.send_msg(meter_mod)
            self.logger.debug(
                'Meter %d installed on dpid=%016x rate=%d kbps',
                meter_id, dpid, bandwidth_kbps)

            # Build match
            match_fields = {'eth_type': ether.ETH_TYPE_IP, 'ip_proto': ip_proto}

            match = parser.OFPMatch(**match_fields)

            # Actions: set DSCP, then output normally
            actions = [
                parser.OFPActionSetField(ip_dscp=dscp_value),
                parser.OFPActionOutput(ofproto.OFPP_NORMAL),
            ]

            # Instructions: meter + apply actions
            inst = [
                parser.OFPInstructionMeter(meter_id=meter_id),
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions),
            ]

            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=flow_priority,
                match=match,
                instructions=inst,
                cookie=cookie,
                cookie_mask=0xFFFFFFFFFFFFFFFF,
            )
            datapath.send_msg(mod)
            self.logger.debug(
                'QoS flow installed on dpid=%016x dscp=%d meter=%d',
                dpid, dscp_value, meter_id)

        self.logger.info('QoS applied for intent %s (protocol=%s, priority=%s)',
                         intent_id, proto_key, priority_level)

    def remove_qos(self, datapaths, intent_id):
        cookie = self.intent_store.get_cookie(intent_id)
        intent = self.intent_store.get_intent(intent_id)
        if cookie is None or intent is None:
            return

        meter_ids = intent.get('meter_ids', [])

        for dpid, datapath in datapaths.items():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            # Delete flows by cookie
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

            # Delete meters
            for meter_id in meter_ids:
                meter_mod = parser.OFPMeterMod(
                    datapath=datapath,
                    command=ofproto.OFPMC_DELETE,
                    meter_id=meter_id,
                )
                datapath.send_msg(meter_mod)

            self.logger.debug(
                'QoS removed on dpid=%016x for intent %s', dpid, intent_id)
