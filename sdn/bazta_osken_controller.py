from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ipv4, icmp, tcp, udp
import requests, time, json

TRUST_API = "http://127.0.0.1:5050/score_flow"
BLOCK_HARD_TIMEOUT = 30
BLOCK_IDLE_TIMEOUT = 10

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
        self.logger.info("Switch connected: dpid=%s", dp.id)

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

                self.logger.info(
                    "[BAZTA] dpid=%s src=%s score=%.1f action=%s triggered=%s",
                    dpid, src_ip, score, action, result.get("triggered", [])
                )

                if action == "BLOCK":
                    self._install_block_rule(dp, parser, src_ip)
                    return  # drop this packet too
                elif action == "RATE_LIMIT":
                    # For now: log + forward. Can add meter later.
                    self.logger.warning("[RATE_LIMIT] src=%s score=%.1f", src_ip, score)

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
        proto = ip_pkt.proto   # 1=ICMP, 6=TCP, 17=UDP

        port = None
        if tcp_pkt:
            port = tcp_pkt.dst_port
        elif udp_pkt:
            port = udp_pkt.dst_port

        return {
            "src_ip":    ip_pkt.src,
            "dst_ip":    ip_pkt.dst,
            "proto":     proto,
            "port":      port,
            "packets":   1,           # per-packet call; extractor aggregates
            "bytes":     len(pkt),
            "duration":  1,
            "pkt_rate":  1,           # extractor computes windowed rate
            "byte_rate": len(pkt),
            "timestamp": time.time()
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
    def _install_block_rule(self, dp, parser, src_ip):
        self.blocked.setdefault(dp.id, set()).add(src_ip)

        # Match all traffic from this src_ip and drop it
        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=src_ip
        )
        # Empty action list = DROP
        self._add_flow(
            dp,
            priority=100,      # higher than forwarding rules
            match=match,
            actions=[],
            hard_timeout=BLOCK_HARD_TIMEOUT,
            idle_timeout=BLOCK_IDLE_TIMEOUT
        )
        self.logger.warning("[BLOCK INSTALLED] dpid=%s src_ip=%s", dp.id, src_ip)

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
