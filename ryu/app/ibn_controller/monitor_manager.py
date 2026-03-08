from ryu.lib import hub


class MonitorManager(object):

    POLL_INTERVAL = 10  # seconds

    def __init__(self, logger):
        self.logger = logger
        self._flow_stats = {}   # dpid -> list of flow stat dicts
        self._port_stats = {}   # dpid -> list of port stat dicts
        self._monitor_thread = None

    def start(self, datapaths_ref):
        """Start the polling thread. datapaths_ref is a dict reference that
        will be read each cycle (shared with IBNController)."""
        self._datapaths_ref = datapaths_ref
        self._monitor_thread = hub.spawn(self._monitor_loop)

    def _monitor_loop(self):
        while True:
            for dp in self._datapaths_ref.values():
                self._request_stats(dp)
            hub.sleep(self.POLL_INTERVAL)

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def handle_flow_stats(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        stats = []
        for stat in body:
            entry = {
                'priority': stat.priority,
                'cookie': stat.cookie,
                'packet_count': stat.packet_count,
                'byte_count': stat.byte_count,
                'duration_sec': stat.duration_sec,
                'table_id': stat.table_id,
                'match': {k: v for k, v in stat.match.items()},
            }
            # Extract action info
            if stat.instructions:
                actions = []
                for inst in stat.instructions:
                    if hasattr(inst, 'actions'):
                        for a in inst.actions:
                            actions.append(str(a))
                entry['actions'] = actions
            stats.append(entry)

        self._flow_stats[dpid] = stats

    def handle_port_stats(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        stats = []
        for stat in body:
            stats.append({
                'port_no': stat.port_no,
                'rx_packets': stat.rx_packets,
                'rx_bytes': stat.rx_bytes,
                'rx_errors': stat.rx_errors,
                'tx_packets': stat.tx_packets,
                'tx_bytes': stat.tx_bytes,
                'tx_errors': stat.tx_errors,
                'rx_dropped': stat.rx_dropped,
                'tx_dropped': stat.tx_dropped,
            })

        self._port_stats[dpid] = stats

    def get_flow_stats(self, dpid, filters=None):
        stats = self._flow_stats.get(dpid, [])
        if not filters:
            return stats

        # Optional filtering by LOGS config fields
        filtered = []
        filter_port = None
        filter_host = None
        if isinstance(filters, list):
            for f in filters:
                if f.get('ports'):
                    filter_port = int(f['ports'])
                if f.get('hosts'):
                    filter_host = f['hosts']

        for entry in stats:
            match = entry.get('match', {})
            if filter_port is not None:
                if (match.get('tcp_dst') != filter_port and
                        match.get('udp_dst') != filter_port and
                        match.get('tcp_src') != filter_port and
                        match.get('udp_src') != filter_port):
                    continue
            if filter_host is not None:
                if (match.get('ipv4_src') != filter_host and
                        match.get('ipv4_dst') != filter_host):
                    continue
            filtered.append(entry)

        return filtered

    def get_port_stats(self, dpid):
        return self._port_stats.get(dpid, [])
