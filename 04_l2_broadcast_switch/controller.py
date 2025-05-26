from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI


def main():
    topo = load_topo(json_path='topology.json')
    controllers = {}
    sw_name = 's1'

    for switch, data in topo.get_p4rtswitches().items():
        controllers[switch] = SimpleSwitchP4RuntimeAPI(
            device_id=data['device_id'],
            grpc_port=data['grpc_port'],
            p4rt_path=data['p4rt_path'],
            json_path=data['json_path'],
        )

    controller = controllers[sw_name]

    # 填充 dmac 表
    for i in 1, 2, 3, 4:
        controller.table_add(
            table_name="dmac",
            action_name="forward",
            match_keys=[f'00:00:0a:00:00:{i:02d}'],
            action_params=[f'{i}'],
        )

    # 获取端口列表
    interfaces_to_port = topo.get_node_intfs(fields=['port'])[sw_name].copy()

    # 过滤端口
    interfaces_to_port.pop('lo', None)
    interfaces_to_port.pop(topo.get_cpu_port_intf(sw_name), None)

    mc_grp_id = 1
    for ingress_port in interfaces_to_port.values():
        port_list = list(interfaces_to_port.values())
        del (port_list[port_list.index(ingress_port)])

        # 添加多播组和端口
        controller.mc_mgrp_create(mc_grp_id, port_list)

        # 填充 select_mcast_grp 表
        controller.table_add(
            table_name="select_mcast_grp",
            action_name="set_mcast_grp",
            match_keys=[str(ingress_port)],
            action_params=[str(mc_grp_id)],
        )
        mc_grp_id = mc_grp_id + 1


if __name__ == '__main__':
    main()
