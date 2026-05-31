from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ipv4, icmp, tcp, udp
import requests, time, json
import numpy as np
from collections import defaultdict
from threading import Lock

class FlowAggregator:
    WINDOW_SEC = 5.0

    def __init__(self):
        self.windows  = defaultdict(list)  # {(src,dst,proto): [(ts, size)]}
        self.ports    = defaultdict(set)   # {src_ip: {ports seen in window}}
        self.lock     = Lock()

    def update(self, src_ip, dst_ip, proto, port, pkt_size, timestamp):
        flow_key = (src_ip, dst_ip, proto)
        cutoff   = timestamp - self.WINDOW_SEC

        with self.lock:
            self.windows[flow_key].append((timestamp, pkt_size))
            self.windows[flow_key] = [(t, s) for t, s in self.windows[flow_key] if t >= cutoff]

            if port:
                self.ports[src_ip].add(port)
            window = list(self.windows[flow_key])

        if len(window) < 2:
            return {
                "pkt_rate":     1.0,
                "byte_rate":    float(pkt_size),
                "unique_ports": 1.0,
                "port_entropy": 0.0,
            }

        timestamps = [t for t, _ in window]
        sizes      = [s for _, s in window]
        duration   = max(timestamps) - min(timestamps)
        duration   = duration if duration > 0 else 1e-3

        # port entropy
        ports_seen = list(self.ports[src_ip])
        n = len(ports_seen)
        if n > 1:
            counts = np.array([ports_seen.count(p) for p in set(ports_seen)], dtype=float)
            probs  = counts / counts.sum()
            entropy = float(-np.sum(probs * np.log2(probs + 1e-9)))
        else:
            entropy = 0.0

        return {
            "pkt_rate":     len(window) / duration,
            "byte_rate":    sum(sizes)  / duration,
            "unique_ports": float(len(self.ports[src_ip])),
            "port_entropy": entropy,
        }

_aggregator = FlowAggregator()

TRUST_API = "http://127.0.0.1:5050/score_flow"
BLOCK_HARD_TIMEOUT = 30
BLOCK_IDLE_TIMEOUT = 10

IP_TO_HOST = {
    '10.0.1.1': 'h1',
    '10.0.1.2': 'h2',
    '10.0.2.1': 'h3',
    '10.0.2.2': 'h4',
    '10.0.3.1': 'h5',
    '10.0.3.2': 'h6',
}

DPID_TO_NAME = {
    1: 's0 (Core)',
    2: 's1 (Seg A)',
    3: 's2 (Seg B)',
    4: 's3 (Seg C)',
}

def get_log_time():
    return time.strftime('%H:%M:%S')

def get_host_name(ip):
    return IP_TO_HOST.get(ip, ip)

def get_switch_name(dpid):
    try:
        val = int(dpid)
        return DPID_TO_NAME.get(val, f"s{val}")
    except ValueError:
        return f"sw_{dpid}"

def get_flow_path(src_ip, dst_ip):
    src_host = get_host_name(src_ip)
    dst_host = get_host_name(dst_ip) if dst_ip else "Unknown"
    
    def ip_to_sw(ip):
        if not ip:
            return None
        parts = ip.split('.')
        if len(parts) >= 3 and parts[0] == '10':
            seg = parts[2]
            if seg in ['1', '2', '3']:
                return f"s{seg}"
        return "s_ext" if ip else None

    src_sw = ip_to_sw(src_ip)
    dst_sw = ip_to_sw(dst_ip)
    
    if not dst_sw or src_sw == dst_sw:
        # Same segment switch
        sw_path = src_sw if src_sw else ""
    else:
        # Different segments -> traffic traverses s0 (Core Switch)
        sw_path = f"{src_sw} → s0 (Core) → {dst_sw}"
        
    if sw_path:
        return f"{src_host} ({src_ip}) → {sw_path} → {dst_host} ({dst_ip or 'Unknown'})"
    else:
        return f"{src_host} ({src_ip}) → {dst_host} ({dst_ip or 'Unknown'})"

class BAZTAController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # mac_to_port[dpid][mac] = port
        self.mac_to_port = {}
        # track blocked IPs per datapath: {dpid: set(src_ip)}
        self.blocked = {}

    # ── Handshake: install table-miss → send to controller ──────────────
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp      = ev.msg.datapath
        ofproto = dp.ofproto
        parser  = dp.ofproto_parser

        # Table-miss flow entry
        match  = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(dp, priority=0, match=match, actions=actions)

        # Configure Meter 1 for rate limiting (e.g. rate = 200 kbps, drop if exceeded)
        self._create_meter(dp, meter_id=1, rate_kbps=200)

        sw = get_switch_name(dp.id)
        self.logger.info("Switch Connected: %s (dpid=%s)", sw, dp.id)

    # ── Main packet handler ─────────────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg     = ev.msg
        dp      = msg.datapath
        ofproto = dp.ofproto
        parser  = dp.ofproto_parser
        in_port = msg.match["in_port"]

        pkt  = packet.Packet(msg.data)
        eth  = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        ip_pkt  = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        # Learn MAC → port mapping
        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        # Only process IP traffic for trust scoring
        if ip_pkt:
            flow_data = self._build_flow_record(ip_pkt, tcp_pkt, udp_pkt, pkt)
            result    = self._query_trust_api(flow_data)

            if result:
                action = result.get("action", "ALLOW")
                score  = result.get("trust_score", 100)
                src_ip = ip_pkt.src
                dst_ip = ip_pkt.dst

                sw = get_switch_name(dpid)
                triggered_str = ", ".join(result.get("triggered", [])) if result.get("triggered") else "None"
                path_str = get_flow_path(src_ip, dst_ip)
                
                if not flow_data.get("is_response", False):
                    self.logger.info(
                        "[%s] [FLOW_MONITOR] [%s] [%s] [Score: %d] [%s] [Triggers: %s]",
                        get_log_time(), sw, path_str, int(score), action, triggered_str
                    )

                    if action == "BLOCK":
                        self._install_block_rule(dp, parser, src_ip, dst_ip, int(score), triggered_str)
                        return  # drop this packet too
                    elif action == "RATE_LIMIT":
                        self._install_rate_limit_rule(dp, parser, src_ip, dst_ip, int(score), triggered_str)


        # Normal L2 forwarding
        dst_mac = eth.dst
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Keep IP packets visible to the trust engine in this demo.
        # Installing a broad IP forwarding flow here would make later flood/scan
        # packets bypass the controller after the first packet.
        if out_port != ofproto.OFPP_FLOOD and not ip_pkt:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_dst=dst_mac,
                eth_type=eth.ethertype,
            )
            self._add_flow(dp, priority=1, match=match, actions=actions)

        # Send packet out
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out  = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        dp.send_msg(out)

    # ── Build flow record for Trust API ─────────────────────────────────
    def _build_flow_record(self, ip_pkt, tcp_pkt, udp_pkt, pkt):
        proto = ip_pkt.proto
        port  = None
        is_response = False

        if tcp_pkt:
            port = tcp_pkt.dst_port
            if tcp_pkt.has_flags(tcp.TCP_RST) or tcp_pkt.has_flags(tcp.TCP_SYN, tcp.TCP_ACK):
                is_response = True
        elif udp_pkt:
            port = udp_pkt.dst_port
        elif proto == 1:
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if icmp_pkt and icmp_pkt.type in [0, 3, 11]:
                is_response = True

        now      = time.time()
        pkt_size = len(pkt)

        # real windowed features
        live = _aggregator.update(
            src_ip    = ip_pkt.src,
            dst_ip    = ip_pkt.dst,
            proto     = proto,
            port      = port,
            pkt_size  = pkt_size,
            timestamp = now,
        )

        return {
            "src_ip":      ip_pkt.src,
            "dst_ip":      ip_pkt.dst,
            "proto":       proto,
            "port":        port,
            "bytes":       pkt_size,
            "timestamp":   now,
            "is_response": is_response,
            # real computed features — TrustEngine reads these directly
            "pkt_rate":     live["pkt_rate"],
            "byte_rate":    live["byte_rate"],
            "unique_ports": live["unique_ports"],
            "port_entropy": live["port_entropy"],
        }


    # ── Query Flask Trust API ────────────────────────────────────────────
    def _query_trust_api(self, flow_data):
        try:
            r = requests.post(TRUST_API, json=flow_data, timeout=0.5)
            return r.json()
        except Exception as e:
            self.logger.warning("Trust API unreachable: %s", e)
            return None

    # ── Install BLOCK rule (microsegment isolation) ──────────────────────
    def _install_block_rule(self, dp, parser, src_ip, dst_ip=None, score=0, triggered="None"):
        self.blocked.setdefault(dp.id, set()).add(src_ip)

        # 1. Egress Block: Drop all traffic originating from this compromised host
        match_egress = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=src_ip
        )
        self._add_flow(
            dp,
            priority=100,      # higher than forwarding rules
            match=match_egress,
            actions=[],
            hard_timeout=BLOCK_HARD_TIMEOUT,
            idle_timeout=BLOCK_IDLE_TIMEOUT
        )

        # 2. Ingress Block: Drop all traffic destined for this compromised host
        match_ingress = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_dst=src_ip
        )
        self._add_flow(
            dp,
            priority=100,      # higher than forwarding rules
            match=match_ingress,
            actions=[],
            hard_timeout=BLOCK_HARD_TIMEOUT,
            idle_timeout=BLOCK_IDLE_TIMEOUT
        )

        sw = get_switch_name(dp.id)
        path_str = get_flow_path(src_ip, dst_ip)
        self.logger.warning(
            "[%s] [BLOCK_INSTALLED] [%s] [%s] [Score: %d] [BLOCK] [Triggers: %s]",
            get_log_time(), sw, path_str, score, triggered
        )

    # ── Helper: add OpenFlow rule ────────────────────────────────────────
    def _add_flow(self, dp, priority, match, actions,
                  idle_timeout=0, hard_timeout=0):
        ofproto = dp.ofproto
        parser  = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions
        )]
        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        dp.send_msg(mod)

    def _create_meter(self, dp, meter_id, rate_kbps):
        ofproto = dp.ofproto
        parser  = dp.ofproto_parser
        
        # OFPMeterBandDrop drops packets exceeding the rate
        band = parser.OFPMeterBandDrop(rate=rate_kbps, burst_size=0)
        req = parser.OFPMeterMod(
            datapath=dp,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_KBPS,
            meter_id=meter_id,
            bands=[band]
        )
        dp.send_msg(req)

    def _install_rate_limit_rule(self, dp, parser, src_ip, dst_ip=None, score=0, triggered="None"):
        meter_id = 1
        ofproto = dp.ofproto

        # Egress Limit: Rate limit all traffic originating from this host
        match_egress = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=src_ip
        )
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        inst = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
            parser.OFPInstructionMeter(meter_id, ofproto.OFPIT_METER)
        ]
        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=95,      # higher than regular forwarding (1) but lower than block (100)
            match=match_egress,
            instructions=inst,
            idle_timeout=BLOCK_IDLE_TIMEOUT,
            hard_timeout=BLOCK_HARD_TIMEOUT
        )
        dp.send_msg(mod)

        # Ingress Limit: Rate limit all traffic destined for this host
        match_ingress = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_dst=src_ip
        )
        mod_ingress = parser.OFPFlowMod(
            datapath=dp,
            priority=95,      # higher than regular forwarding (1) but lower than block (100)
            match=match_ingress,
            instructions=inst,
            idle_timeout=BLOCK_IDLE_TIMEOUT,
            hard_timeout=BLOCK_HARD_TIMEOUT
        )
        dp.send_msg(mod_ingress)

        sw = get_switch_name(dp.id)
        path_str = get_flow_path(src_ip, dst_ip)
        self.logger.warning(
            "[%s] [RATE_LIMIT_INSTALLED] [%s] [%s] [Score: %d] [METER:%d] [Triggers: %s]",
            get_log_time(), sw, path_str, score, meter_id, triggered
        )
