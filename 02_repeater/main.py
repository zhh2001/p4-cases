from p4utils.mininetlib.network_API import NetworkAPI


def main():
    net = NetworkAPI()

    net.addP4Switch('s1')
    net.addHost('h1')
    net.addHost('h2')
    net.addLink('s1', 'h1')
    net.addLink('s1', 'h2')

    net.setLogLevel('info')
    net.setP4SourceAll('main.p4')

    net.enableCli()
    net.enablePcapDumpAll()
    net.enableLogAll()

    net.l2()

    net.startNetwork()


if __name__ == '__main__':
    main()
