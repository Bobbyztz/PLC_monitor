"""Ethernet/IP over TCP scapy dissector"""
import struct

from scapy import all as scapy_all

import utils

class ENIP_ConnectionAddress(scapy_all.Packet):
    """the connection address item in common packet format"""
    """2-6.2.2 Connected Address Item"""
    name = "ENIP_ConnectionAddress Item"
    fields_desc = [scapy_all.LEIntField("connection_id", 0)]

class ENIP_ConnectionData(scapy_all.Packet):
    """the connection data item in common packet format"""
    """2-6 Common Packet Format"""
    name = "ENIP_ConnectionData Item"
    fields_desc = [scapy_all.LEShortField("sequence", 0)]

class ENIP_SendUnitData_Item(scapy_all.Packet):
    """Table 2-4.15 SendUnitData Command"""
    name = "ENIP_SendUnitData_Item"
    fields_desc = [
        scapy_all.LEShortEnumField("type_id", 0, {
            0x0000: "null_address",  # NULL Address
            0x00a1: "conn_address",  # Address for connection based requests
            0x00b1: "conn_packet",  # Connected Transport packet
            0x00b2: "unconn_message",  # Unconnected Messages (eg. used within CIP command SendRRData)
            0x0100: "listservices_response",  # ListServices response
        }),
        scapy_all.LEShortField("length", None),
    ]

    def extract_padding(self, p):
        return p[:self.length], p[self.length:]

    #way to build a new packet
    def post_build(self, p, pay):
        if self.length is None and pay:
            l = len(pay)
            p = p[:2] + struct.pack("<H", l) + p[4:]
        return p + pay


class ENIP_SendUnitData(scapy_all.Packet):
    """Data in ENIP header specific to the specified command"""
    """Table 2-4.15 SendUnitData Command"""
    name = "ENIP_SendUnitData"
    fields_desc = [
        scapy_all.LEIntField("interface_handle", 0),
        scapy_all.LEShortField("timeout", 0),
        utils.LEShortLenField("count", None, count_of="items"),
        scapy_all.PacketListField("items", [], ENIP_SendUnitData_Item,
                                  count_from=lambda p: p.count),
    ]


class ENIP_SendRRData(scapy_all.Packet):
    name = "ENIP_SendRRData"
    """Table 2-4.13 SendRRData Request"""
    """Table 2-4.14 SendRRData Reply"""
    fields_desc = ENIP_SendUnitData.fields_desc


class ENIP_RegisterSession(scapy_all.Packet):
    name = "ENIP_RegisterSession"
    fields_desc = [
        scapy_all.LEShortField("protocol_version", 1),
        scapy_all.LEShortField("options", 0),
    ]


class ENIP_TCP(scapy_all.Packet):
    """Ethernet/IP packet over TCP"""
    name = "ENIP_TCP"

    # Table 2-3.2 Encapsulation Commands
    fields_desc = [
        scapy_all.LEShortEnumField("command_id", None, {
            0x0004: "ListServices",
            0x0063: "ListIdentity",
            0x0064: "ListInterfaces",
            0x0065: "RegisterSession",
            0x0066: "UnregisterSession",
            0x006f: "SendRRData",  # Send Request/Reply data
            0x0070: "SendUnitData",
        }),

        # 2-3.1 Encapsulation Packet Structure with the default setting
        scapy_all.LEShortField("length", None),
        scapy_all.LEIntField("session", 0),
        scapy_all.LEIntEnumField("status", 0, {0: "success"}),
        scapy_all.LELongField("sender_context", 0),
        scapy_all.LEIntField("options", 0),
    ]

    def extract_padding(self, p):
        return p[:self.length], p[self.length:]

    # way to build a ENIP_TCP packet
    def post_build(self, p, pay):
        if self.length is None and pay:
            l = len(pay)
            p = p[:2] + struct.pack("<H", l) + p[4:]
        return p + pay

scapy_all.bind_layers(scapy_all.TCP, ENIP_TCP, dport=44818) # pdf, 2-3.1 Encapsulation Packet Structure
scapy_all.bind_layers(scapy_all.TCP, ENIP_TCP, sport=44818) # pdf, 2-3.1 Encapsulation Packet Structure
scapy_all.bind_layers(ENIP_TCP, ENIP_RegisterSession, command_id=0x0065) # pdf, 2-3.2 Command Field, RegisterSession
scapy_all.bind_layers(ENIP_TCP, ENIP_SendRRData, command_id=0x006f) # pdf, 2-3.2 Command Field, SendRRData
scapy_all.bind_layers(ENIP_TCP, ENIP_SendUnitData, command_id=0x0070) #pdf, 2-3.2 Command Field, SendUnitData
scapy_all.bind_layers(ENIP_SendUnitData_Item, ENIP_ConnectionAddress, type_id=0x00a1) #Table 2-6.3 Item ID Numbers,address, Connection-based (used for connected messages)
scapy_all.bind_layers(ENIP_SendUnitData_Item, ENIP_ConnectionData, type_id=0x00b1) #Table 2-6.3 Item ID Numbers, data, Connected Transport packet