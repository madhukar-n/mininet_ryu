from mininet.topo import Topo

class TriangleTopo(Topo):

    def build(self):

        h = ['h1','h2','h3']
        s = ['s1','s2','s3']

        hosts = []
        switches = []
        for i in range(3):
            hosts.append(self.addHost(h[i]))
            switches.append(self.addSwitch(s[i]))
        for i in range(0,3):
            self.addLink(hosts[i],switches[i])
            self.addLink(switches[i],switches[(i + 1)%3])
        
        

class Topology(Topo):

    def build(self):
        hosts = [self.addHost(f"h{i}") for i in range(1, 15)]

        # switches s1 ... s11
        switches = [self.addSwitch(f"s{i}") for i in range(1, 8)]

        # switch-to-switch links (1-based → convert to 0-based)
        links = [
            (1,2),(1,3),(3,4),(4,6),(6,5),(3,5),(5,7),(2,3)
        ]

        for u, v in links:
            self.addLink(switches[u-1], switches[v-1])

        # attach 2 hosts per switch (22 hosts, 11 switches)
        for i in range(len(switches)):
            self.addLink(switches[i], hosts[2*i])
            self.addLink(switches[i], hosts[2*i + 1])

topos = {"triang" : (lambda : TriangleTopo()) , "topo" : (lambda : Topology())}
        