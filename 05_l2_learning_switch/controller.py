import sys

from scapy.compat import raw
from scapy.fields import BitField
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.sendrecv import sniff

from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI


class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField('macAddr', 0, 48), BitField('ingress_port', 0, 16)]


class L2Controller:

    def __init__(self, sw_name):
        self.topo = load_topo('topology.json')
        self.sw_name = sw_name
        self.cpu_port = self.topo.get_cpu_port_index(self.sw_name)
        device_id = self.topo.get_p4switch_id(sw_name)
        grpc_port = self.topo.get_grpc_port(sw_name)
        sw_data = self.topo.get_p4rtswitches()[sw_name]
        self.controller = SimpleSwitchP4RuntimeAPI(
            device_id=device_id,
            grpc_port=grpc_port,
            p4rt_path=sw_data['p4rt_path'],
            json_path=sw_data['json_path'],
        )
        self.init()

    def reset(self):
        # 重置 gRPC 服务器
        self.controller.reset_state()

        thrift_port = self.topo.get_thrift_port(self.sw_name)
        controller_thrift = SimpleSwitchThriftAPI(thrift_port)
        controller_thrift.reset_state()

    def init(self):
        self.reset()
        self.add_broadcast_groups()
        self.add_clone_session()

    def config_digest(self):
        # 单条消息最多可发送 10 条摘要信息。最大超时设置为 1 毫秒。
        self.controller.digest_enable(
            digest_name='learn_t',
            max_timeout_ns=1000000,
            max_list_size=10,
            ack_timeout_ns=1000000,
        )

    def add_clone_session(self):
        if self.cpu_port:
            self.controller.cs_create(100, [self.cpu_port])

    def add_broadcast_groups(self):
        interfaces_to_port = self.topo.get_node_intfs(fields=['port'])[self.sw_name].copy()
        # 过滤端口
        interfaces_to_port.pop('lo', None)
        interfaces_to_port.pop(self.topo.get_cpu_port_intf(self.sw_name), None)

        mc_grp_id = 1
        for ingress_port in interfaces_to_port.values():
            port_list = list(interfaces_to_port.values())
            del (port_list[port_list.index(ingress_port)])

            self.controller.mc_mgrp_create(mc_grp_id, port_list)

            # 填充 broadcast 表
            self.controller.table_add("broadcast", "set_mcast_grp", [str(ingress_port)], [str(mc_grp_id)])
            mc_grp_id = mc_grp_id + 1

    def learn(self, learning_data):
        for mac_addr, ingress_port in learning_data:
            print("mac: %012X ingress_port: %s " % (mac_addr, ingress_port))
            self.controller.table_add("smac", "NoAction", [str(mac_addr)])
            self.controller.table_add("dmac", "forward", [str(mac_addr)], [str(ingress_port)])

    def unpack_digest(self, dig_list):
        learning_data = [(int.from_bytes(dig.struct.members[0].bitstring, byteorder='big'),
                          int.from_bytes(dig.struct.members[1].bitstring, byteorder='big'))
                         for dig in dig_list.data]
        return learning_data

    def recv_msg_digest(self, dig_list):
        learning_data = self.unpack_digest(dig_list)
        self.learn(learning_data)

    def run_digest_loop(self):
        self.config_digest()
        while True:
            dig_list = self.controller.get_digest_list()
            self.recv_msg_digest(dig_list)

    def recv_msg_cpu(self, pkt):
        packet = Ether(raw(pkt))
        if packet.type == 0x1234:
            cpu_header = CpuHeader(bytes(packet.load))
            self.learn([(cpu_header.macAddr, cpu_header.ingress_port)])

    def run_cpu_port_loop(self):
        cpu_port_intf = self.topo.get_cpu_port_intf(self.sw_name).replace("eth0", "eth1")
        sniff(iface=cpu_port_intf, prn=self.recv_msg_cpu)


if __name__ == "__main__":
    sw_name = sys.argv[1]
    receive_from = sys.argv[2]
    if receive_from == "digest":
        controller = L2Controller(sw_name).run_digest_loop()
    elif receive_from == "cpu":
        controller = L2Controller(sw_name).run_cpu_port_loop()
