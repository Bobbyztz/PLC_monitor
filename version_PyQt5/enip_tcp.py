#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Copyright (c) 2015 Nicolas Iooss, SUTD
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""Ethernet/IP over TCP scapy dissector"""
import struct

from scapy import all as scapy_all

import utils

class ENIP_ConnectionAddress(scapy_all.Packet):
    name = "ENIP_ConnectionAddress Item"
    fields_desc = [scapy_all.LEIntField("connection_id", 0)]

class ENIP_ConnectionData(scapy_all.Packet):
    name = "ENIP_ConnectionData Item"
    fields_desc = [scapy_all.LEShortField("sequence", 0)]


class ENIP_SendUnitData_Item(scapy_all.Packet):
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

    def post_build(self, p, pay):
        if self.length is None and pay:
            l = len(pay)
            p = p[:2] + struct.pack("<H", l) + p[4:]
        return p + pay


class ENIP_SendUnitData(scapy_all.Packet):
    """Data in ENIP header specific to the specified command"""
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
        scapy_all.LEShortField("length", None),
        scapy_all.LEIntField("session", 0),
        scapy_all.LEIntEnumField("status", 0, {0: "success"}),
        scapy_all.LELongField("sender_context", 0),
        scapy_all.LEIntField("options", 0),
    ]

    def extract_padding(self, p):
        return p[:self.length], p[self.length:]

    def post_build(self, p, pay):
        if self.length is None and pay:
            l = len(pay)
            p = p[:2] + struct.pack("<H", l) + p[4:]
        return p + pay

scapy_all.bind_layers(scapy_all.TCP, ENIP_TCP, dport=44818)
scapy_all.bind_layers(scapy_all.TCP, ENIP_TCP, sport=44818)
scapy_all.bind_layers(ENIP_TCP, ENIP_RegisterSession, command_id=0x0065)
scapy_all.bind_layers(ENIP_TCP, ENIP_SendRRData, command_id=0x006f)
scapy_all.bind_layers(ENIP_TCP, ENIP_SendUnitData, command_id=0x0070)
scapy_all.bind_layers(ENIP_SendUnitData_Item, ENIP_ConnectionAddress, type_id=0x00a1)
scapy_all.bind_layers(ENIP_SendUnitData_Item, ENIP_ConnectionData, type_id=0x00b1)