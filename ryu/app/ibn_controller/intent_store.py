import time
import threading


class IntentStore(object):

    def __init__(self):
        self._intents = {}
        self._lock = threading.Lock()
        self._next_meter_id = 1

    def _generate_cookie(self, intent_id):
        return hash(intent_id) & 0xFFFFFFFFFFFFFFFF

    def allocate_meter_id(self):
        with self._lock:
            meter_id = self._next_meter_id
            self._next_meter_id += 1
            return meter_id

    def add_intent(self, intent_id, config):
        with self._lock:
            cookie = self._generate_cookie(intent_id)
            self._intents[intent_id] = {
                'intent_id': intent_id,
                'config': config,
                'cookie': cookie,
                'meter_ids': [],
                'status': 'active',
                'created_at': time.time(),
            }
            return self._intents[intent_id]

    def add_meter_id(self, intent_id, meter_id):
        with self._lock:
            if intent_id in self._intents:
                self._intents[intent_id]['meter_ids'].append(meter_id)

    def get_intent(self, intent_id):
        with self._lock:
            return self._intents.get(intent_id)

    def get_all_intents(self):
        with self._lock:
            return dict(self._intents)

    def remove_intent(self, intent_id):
        with self._lock:
            return self._intents.pop(intent_id, None)

    def get_cookie(self, intent_id):
        with self._lock:
            intent = self._intents.get(intent_id)
            if intent:
                return intent['cookie']
            return None
