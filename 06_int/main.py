from p4utils.mininetlib.network_API import NetworkAPI


def main():
    net = NetworkAPI()

    for i in 1, 2, 3:
        switch_name = f's{i}'
        net.addP4Switch(switch_name)
        net.setP4CliInput(switch_name, cli_input=f'./commands/{switch_name}.sh')
        net.setP4Source(switch_name, 'main.p4')

    net.addHost('h1')
    net.addHost('h2')
    net.addHost('h3')
    net.addHost('h4')

    net.addLink('h1', 's1')
    net.addLink('h2', 's2')
    net.addLink('s1', 's2')
    net.addLink('s1', 's3')
    net.addLink('h3', 's3')
    net.addLink('h4', 's3')

    net.mixed()

    net.setLogLevel('info')
    net.setBwAll(1000)

    net.disablePcapDumpAll()
    net.disableLogAll()

    net.enableCli()

    net.startNetwork()


if __name__ == '__main__':
    main()
