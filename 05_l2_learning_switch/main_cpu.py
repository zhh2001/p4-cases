from p4utils.mininetlib.network_API import NetworkAPI


def main():
    net = NetworkAPI()

    net.addP4RuntimeSwitch('s1')

    for i in 1, 2, 3, 4:
        host_name = f'h{i}'
        net.addHost(host_name)
        net.addLink('s1', host_name)

    net.l2()

    net.setLogLevel('info')
    net.setCompiler(p4rt=True)
    net.setP4SourceAll('main_cpu.p4')

    net.disableArpTables()
    net.enableCpuPort('s1')
    net.enableLog('s1', log_dir='./log')
    net.enablePcapDump('s1', pcap_dir='./pcap')
    net.enableCli()

    net.startNetwork()


if __name__ == '__main__':
    main()
