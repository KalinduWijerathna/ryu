import json
import time

from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import route

from .ibn_app import ibn_instance_name

ibn_url_base = '/ibn'


class IBNRestController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(IBNRestController, self).__init__(req, link, data, **config)
        self.ibn_app = data[ibn_instance_name]

    # --- Intent CRUD ---

    @route('ibn', ibn_url_base + '/intents', methods=['POST'])
    def post_intent(self, req, **kwargs):
        try:
            body = req.json if req.body else {}
        except ValueError:
            return self._error_response(400, 'Invalid JSON')

        result = self.ibn_app.apply_intent(body)
        if 'error' in result:
            return self._error_response(400, result['error'])

        return self._json_response(result, status=201)

    @route('ibn', ibn_url_base + '/intents', methods=['GET'])
    def list_intents(self, req, **kwargs):
        intents = self.ibn_app.intent_store.get_all_intents()
        result = {}
        for intent_id, data in intents.items():
            result[intent_id] = {
                'intent_id': data['intent_id'],
                'status': data['status'],
                'cookie': data['cookie'],
                'created_at': data['created_at'],
            }
        return self._json_response(result)

    @route('ibn', ibn_url_base + '/intents/{intent_id}', methods=['GET'])
    def get_intent(self, req, **kwargs):
        intent_id = kwargs.get('intent_id')
        intent = self.ibn_app.intent_store.get_intent(intent_id)
        if intent is None:
            return self._error_response(404, 'Intent not found')

        result = {
            'intent_id': intent['intent_id'],
            'config': intent['config'],
            'status': intent['status'],
            'cookie': intent['cookie'],
            'meter_ids': intent['meter_ids'],
            'created_at': intent['created_at'],
        }
        return self._json_response(result)

    @route('ibn', ibn_url_base + '/intents/{intent_id}', methods=['DELETE'])
    def delete_intent(self, req, **kwargs):
        intent_id = kwargs.get('intent_id')
        result = self.ibn_app.delete_intent(intent_id)
        if 'error' in result:
            return self._error_response(404, result['error'])
        return self._json_response(result)

    # --- Stats ---

    @route('ibn', ibn_url_base + '/stats/flows/{dpid}', methods=['GET'])
    def get_flow_stats(self, req, **kwargs):
        dpid = self._parse_dpid(kwargs.get('dpid'))
        if dpid is None:
            return self._error_response(400, 'Invalid dpid')

        if dpid not in self.ibn_app.datapaths:
            return self._error_response(404, 'Switch not found')

        stats = self.ibn_app.monitor_manager.get_flow_stats(dpid)
        return self._json_response({'dpid': dpid, 'flows': stats})

    @route('ibn', ibn_url_base + '/stats/ports/{dpid}', methods=['GET'])
    def get_port_stats(self, req, **kwargs):
        dpid = self._parse_dpid(kwargs.get('dpid'))
        if dpid is None:
            return self._error_response(400, 'Invalid dpid')

        if dpid not in self.ibn_app.datapaths:
            return self._error_response(404, 'Switch not found')

        stats = self.ibn_app.monitor_manager.get_port_stats(dpid)
        return self._json_response({'dpid': dpid, 'ports': stats})

    # --- Switches ---

    @route('ibn', ibn_url_base + '/switches', methods=['GET'])
    def list_switches(self, req, **kwargs):
        switches = []
        for dpid, dp in self.ibn_app.datapaths.items():
            switches.append({
                'dpid': dpid,
                'dpid_hex': '%016x' % dpid,
            })
        return self._json_response({'switches': switches})

    # --- Health ---

    @route('ibn', ibn_url_base + '/health', methods=['GET'])
    def health_check(self, req, **kwargs):
        return self._json_response({
            'status': 'ok',
            'switches': len(self.ibn_app.datapaths),
            'intents': len(self.ibn_app.intent_store.get_all_intents()),
            'timestamp': time.time(),
        })

    # --- Helpers ---

    def _parse_dpid(self, dpid_str):
        try:
            return int(dpid_str)
        except (ValueError, TypeError):
            return None

    def _json_response(self, data, status=200):
        body = json.dumps(data, default=str)
        return Response(
            content_type='application/json',
            text=body,
            status=status,
        )

    def _error_response(self, status, message):
        body = json.dumps({'error': message})
        return Response(
            content_type='application/json',
            text=body,
            status=status,
        )
