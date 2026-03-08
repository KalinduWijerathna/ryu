# Protocol and QoS profile constants for IBN Controller

from ryu.lib.packet import in_proto

# Maps protocol names to (ip_proto, default_port) tuples
PROTOCOL_MAP = {
    'http':   (in_proto.IPPROTO_TCP, 80),
    'https':  (in_proto.IPPROTO_TCP, 443),
    'ssh':    (in_proto.IPPROTO_TCP, 22),
    'ftp':    (in_proto.IPPROTO_TCP, 21),
    'dns':    (in_proto.IPPROTO_UDP, 53),
    'smtp':   (in_proto.IPPROTO_TCP, 25),
    'imap':   (in_proto.IPPROTO_TCP, 143),
    'pop3':   (in_proto.IPPROTO_TCP, 110),
    'tcp':    (in_proto.IPPROTO_TCP, None),
    'udp':    (in_proto.IPPROTO_UDP, None),
    'icmp':   (in_proto.IPPROTO_ICMP, None),
    'voip':   (in_proto.IPPROTO_UDP, 5060),
    'voice':  (in_proto.IPPROTO_UDP, 5060),
    'video':  (in_proto.IPPROTO_TCP, 443),
    'db':     (in_proto.IPPROTO_TCP, 3306),
    'mail':   (in_proto.IPPROTO_TCP, 25),
}

# QoS profiles derived from qosProfile.yaml
# DSCP = ToS >> 2 (ToS is the full 8-bit field, DSCP is the upper 6 bits)
QOS_PROFILES = {
    'voip': {
        'tos': 184,
        'dscp': 184 >> 2,   # 46 (EF)
        'bandwidth': 1000000,  # 1G in kbps
        'protocol': 'udp',
    },
    'voice': {
        'tos': 184,
        'dscp': 184 >> 2,   # 46 (EF)
        'bandwidth': 1000000,
        'protocol': 'udp',
    },
    'video': {
        'tos': 136,
        'dscp': 136 >> 2,   # 34 (AF41)
        'bandwidth': 9500000,  # 9.5G in kbps
        'protocol': 'tcp',
    },
    'http': {
        'tos': 72,
        'dscp': 72 >> 2,    # 18 (AF21)
        'bandwidth': 8000000,
        'protocol': 'tcp',
    },
    'db': {
        'tos': 32,
        'dscp': 32 >> 2,    # 8 (CS1)
        'bandwidth': 6000000,
        'protocol': 'tcp',
    },
    'ssh': {
        'tos': 64,
        'dscp': 64 >> 2,    # 16 (CS2)
        'bandwidth': 4000000,
        'protocol': 'tcp',
    },
    'mail': {
        'tos': 192,
        'dscp': 192 >> 2,   # 48 (CS6)
        'bandwidth': 5000000,
        'protocol': 'tcp',
    },
    'ftp': {
        'tos': 40,
        'dscp': 40 >> 2,    # 10 (AF11)
        'bandwidth': 9000000,
        'protocol': 'tcp',
    },
}

# Priority levels for QoS flow rules
QOS_PRIORITY_MAP = {
    'high': 15000,
    'medium': 12000,
    'low': 10000,
}

# Priority base by user role for ACL rules
ACL_ROLE_PRIORITY = {
    'admin': 40000,
    'premium': 30000,
    'user': 20000,
}

# Offset added to DENY rules within each role band
ACL_DENY_OFFSET = 1000
