from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

def create_topology():
    
    net = Mininet(
        controller=RemoteController,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=False  
    )
    
    info('*** Adicionando controller\n')
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6653
    )
    
    info('*** Adicionando hosts\n')
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
    
    info('*** Adicionando switch\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    
    info('*** Criando links\n')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)
    
    info('*** Iniciando rede\n')
    net.build()
    c0.start()
    s1.start([c0])
    
    info('*** Configurando flows L3 no switch\n')
    s1.dpctl('del-flows')
    
    s1.dpctl('add-flow', 'priority=100,arp,actions=flood')
    
    s1.dpctl('add-flow', 'priority=0,actions=output:CONTROLLER')
    
    info('*** Testando conectividade\n')
    net.pingAll()
    
    info('*** Gerando trafego TCP\n')
    info('h1 iniciando servidor iperf...\n')
    h1.cmd('iperf -s &')
    
    info('Aguardando servidor iniciar...\n')
    net.waitConnected()
    
    info('h2 conectando ao servidor...\n')
    h2.cmd('iperf -c 10.0.0.1 -t 5 &')
    
    info('\n*** Entrando no CLI do Mininet\n')
    info('*** Comandos úteis:\n')
    info('  pingall          - testa conectividade\n')
    info('  h1 iperf -s &    - inicia servidor\n')
    info('  h2 iperf -c 10.0.0.1 -t 10  - cliente\n')
    info('  dump             - mostra informações da rede\n')
    info('  dpctl dump-flows - mostra flows do switch\n')
    info('\n')
    
    CLI(net)
    
    info('*** Parando rede\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()