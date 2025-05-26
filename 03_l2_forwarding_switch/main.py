from p4utils.mininetlib.network_API import NetworkAPI


def main():
    net = NetworkAPI()

    net.execScript('/home/p4/src/p4dev-python-venv/bin/python controller.py', reboot=True)

    net.addP4RuntimeSwitch('s1')

    net.addHost('h1')
    net.addHost('h2')
    net.addHost('h3')
    net.addHost('h4')

    net.addLink('s1', 'h1')
    net.addLink('s1', 'h2')
    net.addLink('s1', 'h3')
    net.addLink('s1', 'h4')

    net.setLogLevel('info')
    net.setCompiler(p4rt=True)
    net.setP4SourceAll('main.p4')

    net.l2()

    net.enableLog('s1', './log')
    net.enablePcapDump('s1', './pcap')
    net.enableCli()

    net.startNetwork()


if __name__ == '__main__':
    main()
