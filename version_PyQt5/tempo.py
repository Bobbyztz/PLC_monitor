if packet.payload.payload.haslayer(enip_tcp.ENIP_TCP):
    protocol = packet.payload.payload.payload.name
    if packet.payload.payload.payload.haslayer(enip_tcp.ENIP_RegisterSession):
        protocol = packet.payload.payload.payload.payload.name
    elif packet.payload.payload.payload.haslayer(enip_tcp.ENIP_SendRRData):
        protocol = "CIP CM"  # ENIP_SendRRData
    elif packet.payload.payload.payload.haslayer(enip_tcp.ENIP_SendUnitData):
        protocol = packet.payload.payload.payload.payload.name
        items = packet.payload.payload.payload.payload.items
        if items[0].name == "ENIP_SendUnitData_Item":
            protocol = items[0].name  # ENIP_SendUnitData_Item
            if items[0].type_id == 0x00a1:
                protocol = "CIP"
            # if items[0].type_id == 0x00b2 :
            #      protocol = items[0].payload.name #CIP
            #      if packet[cip.CIP].direction==1:
            #         if packet[cip.CIP].service ==0x01:
            #             protocol=packet[cip.CIP].payload.name #CIP_RespAttributesAll
            #         elif packet[cip.CIP].service == 0x03:
            #             protocol = packet[cip.CIP].payload.name #CIP_RespAttributesList
            #         elif packet[cip.CIP].service == 0x054:
            #             protocol = packet[cip.CIP].payload.name #CIP_RespSingleAtribute
            #         elif packet[cip.CIP].service == 0x0e:
            #             protocol = packet[cip.CIP].payload.name #CIP_RespForwardOpen
            #      elif packet[cip.CIP].direction==0:
            #          if packet[cip.CIP].service == 0x03:
            #              protocol = packet[cip.CIP].payload.name  # CIP_ReqGetAttributeList
            #          elif packet[cip.CIP].service == 0x4c:
            #              protocol = packet[cip.CIP].payload.name  # CIP_ReqReadOtherTag
            #          elif packet[cip.CIP].service == 0x4f:
            #              protocol = packet[cip.CIP].payload.name  # CIP_ReqReadOtherTag
            #          elif packet[cip.CIP].service == 0x54:
            #              protocol = packet[cip.CIP].payload.name  # CIP_ReqForwardOpen
            # elif items[0].type_id == 0x00a1:
            #     protocol = items[0].payload.name #ENIP_ConnectionAddress
            #     if items[1].type_id == 0x00b1:
            #         protocol = items[0].payload.name #ENIP_ConnectionData