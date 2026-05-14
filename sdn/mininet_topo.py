from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.topo import Topo
from mininet.log import setLogLevel
from mininet.cli import CLI

class CampusIoTTopo(Topo):
    """
    3 microsegments (switches), each with IoT devices.
    All switches connect to a core switch.

    s_core
      ├── s1 (segment A: IoT devices h1, h2)
      ├── s2 (segment B: IoT devices h3, h4)
      └── s3 (segment C: IoT devices h5, h6)
    """
    def build(self):
        core = self.addSwitch("s0")  # core/aggregation switch

        for seg in range(1, 4):
            sw = self.addSwitch(f"s{seg}")
            self.addLink(sw, core)

            for host_idx in range(1, 3):
                h = self.addHost(
                    f"h{(seg-1)*2 + host_idx}",
                    ip=f"10.0.{seg}.{host_idx}/24"
                )
                self.addLink(h, sw)

def run():
    setLogLevel("info")
    topo = CampusIoTTopo()
    net  = Mininet(
        topo=topo,
        switch=OVSKernelSwitch,
        controller=RemoteController("c0", ip="127.0.0.1", port=6653),
        autoSetMacs=True
    )
    net.start()

    # Set OVS to use OpenFlow 1.3 on all switches
    for sw in net.switches:
        sw.cmd(f"ovs-vsctl set bridge {sw.name} protocols=OpenFlow13")

    print("\n" + "="*60)
    print("  BAZTA — Campus IoT Zero Trust Network")
    print("="*60)
    print("\n  Normal traffic:")
    print("    h1 ping h2")
    print("    pingall")
    print("\n  Attack scenarios:")
    print("    h1 bash attacks.sh icmp_flood 10.0.1.2")
    print("    h1 bash attacks.sh port_scan 10.0.1.2")
    print("    h1 bash attacks.sh byte_flood 10.0.1.2")
    print("    h1 bash attacks.sh full_demo 10.0.1.2")
    print("\n  Dashboard: http://localhost:5000")
    print("="*60 + "\n")

    CLI(net)
    net.stop()

if __name__ == "__main__":
    run()