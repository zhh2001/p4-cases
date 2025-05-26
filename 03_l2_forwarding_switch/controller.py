from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI


def main():
    topo = load_topo('topology.json')
    controllers = {
        switch: SimpleSwitchP4RuntimeAPI(
            device_id=data['device_id'],
            grpc_port=data['grpc_port'],
            json_path=data['json_path'],
            p4rt_path=data['p4rt_path'],
        ) for switch, data in topo.get_p4rtswitches().items()
    }

    controller = controllers['s1']

    for i in 1, 2, 3, 4:
        controller.table_add('dmac', 'forward', [f'00:00:0a:00:00:{i:02d}'], [f'{i}'])


if __name__ == '__main__':
    main()
