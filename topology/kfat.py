from mininet.topo import Topo

class KFatTree(Topo):

    def build(self):
        k = 4
        no_of_core_switches = (k//2) * (k//2)
        switch_id = 1
        core_switches = []
        host_id = 1
        for i in range(no_of_core_switches):
            core_switches.append(self.addSwitch(f"c{switch_id}"))
            switch_id = switch_id + 1


        #aggregate switches for each pod
        for i in range(k):
            
            aggregate_switches = []

            for j in range(k//2):
                aggregate_switches.append(self.addSwitch(f'a{switch_id}'))
                switch_id = switch_id + 1

                #connect aggregate switches in ith pod to core switches
                for core_switch_id in range(j , no_of_core_switches , (k//2)):
                    self.addLink(aggregate_switches[j] , core_switches[core_switch_id])
            

            
            for _ in range(k//2):
                edge_switch = self.addSwitch(f'e{switch_id}')
                switch_id = switch_id + 1

                #connect edge switches and aggregate switches
                print(f"{switch_id}")
                for agg_switch in  aggregate_switches:
                        self.addLink(edge_switch,agg_switch)

                for _ in range(k//2):
                     host = self.addHost(f'h{host_id}')
                     self.addLink(host,edge_switch)
                     host_id = host_id + 1
                     

                
            
            

topos = {"kfat" : (lambda : KFatTree())}

