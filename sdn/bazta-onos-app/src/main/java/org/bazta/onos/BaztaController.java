package org.bazta.onos;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.TCP;
import org.onlab.packet.UDP;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Component(immediate = true)
public class BaztaController {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    private ApplicationId appId;
    private BaztaPacketProcessor processor = new BaztaPacketProcessor();
    private final ObjectMapper mapper = new ObjectMapper();

    private static final String TRUST_API = "http://127.0.0.1:5050/score_flow";
    
    private final Set<String> blockedIps = ConcurrentHashMap.newKeySet();

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("org.bazta.onos");
        
        // Priority 200 is higher than reactive forwarding (128)
        packetService.addProcessor(processor, PacketProcessor.director(200));
        
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        log.info("BAZTA ONOS Controller Started");
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(processor);
        processor = null;
        log.info("BAZTA ONOS Controller Stopped");
    }

    private class BaztaPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null || ethPkt.getEtherType() != Ethernet.TYPE_IPV4) {
                return;
            }

            IPv4 ipv4Pkt = (IPv4) ethPkt.getPayload();
            String srcIp = IPv4.fromIPv4Address(ipv4Pkt.getSourceAddress());
            String dstIp = IPv4.fromIPv4Address(ipv4Pkt.getDestinationAddress());
            byte proto = ipv4Pkt.getProtocol();

            int port = 0;
            if (proto == IPv4.PROTOCOL_TCP) {
                TCP tcpPkt = (TCP) ipv4Pkt.getPayload();
                port = tcpPkt.getDestinationPort();
            } else if (proto == IPv4.PROTOCOL_UDP) {
                UDP udpPkt = (UDP) ipv4Pkt.getPayload();
                port = udpPkt.getDestinationPort();
            }

            int packetLength = pkt.unparsed().array().length;

            if (blockedIps.contains(srcIp)) {
                context.block();
                return;
            }

            Map<String, Object> flowData = new HashMap<>();
            flowData.put("src_ip", srcIp);
            flowData.put("dst_ip", dstIp);
            flowData.put("proto", proto);
            flowData.put("port", port == 0 ? null : port);
            flowData.put("packets", 1);
            flowData.put("bytes", packetLength);
            flowData.put("duration", 1);
            flowData.put("pkt_rate", 1);
            flowData.put("byte_rate", packetLength);
            flowData.put("timestamp", System.currentTimeMillis() / 1000.0);

            callTrustApiAndEnforce(context, flowData, srcIp, pkt.receivedFrom().deviceId());
        }

        private void callTrustApiAndEnforce(PacketContext context, Map<String, Object> flowData, String srcIp, DeviceId deviceId) {
            try {
                URL url = new URL(TRUST_API);
                HttpURLConnection con = (HttpURLConnection) url.openConnection();
                con.setRequestMethod("POST");
                con.setRequestProperty("Content-Type", "application/json");
                con.setDoOutput(true);
                con.setConnectTimeout(500); 
                con.setReadTimeout(500);

                String jsonInputString = mapper.writeValueAsString(flowData);
                try (OutputStream os = con.getOutputStream()) {
                    byte[] input = jsonInputString.getBytes(StandardCharsets.UTF_8);
                    os.write(input, 0, input.length);
                }

                int status = con.getResponseCode();
                if (status == 200) {
                    JsonNode responseNode = mapper.readTree(con.getInputStream());
                    String action = responseNode.has("action") ? responseNode.get("action").asText() : "ALLOW";
                    double score = responseNode.has("trust_score") ? responseNode.get("trust_score").asDouble() : 100.0;

                    log.info("[BAZTA] dpid={} src={} score={} action={}", deviceId, srcIp, score, action);

                    if ("BLOCK".equals(action)) {
                        installBlockRule(deviceId, srcIp);
                        context.block(); 
                    } else if ("RATE_LIMIT".equals(action)) {
                        log.warn("[RATE_LIMIT] src={} score={}", srcIp, score);
                    }
                }
            } catch (Exception e) {
                log.warn("Trust API unreachable: {}", e.getMessage());
            }
        }
    }

    private void installBlockRule(DeviceId deviceId, String srcIp) {
        blockedIps.add(srcIp);

        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPSrc(org.onlab.packet.IpPrefix.valueOf(srcIp + "/32"))
                .build();

        TrafficTreatment treatment = DefaultTrafficTreatment.builder().wipeDeferred().build();

        FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(50000) 
                .fromApp(appId)
                .makeTemporary(300) 
                .build();

        flowRuleService.applyFlowRules(flowRule);
        log.warn("[BLOCK INSTALLED] dpid={} src_ip={}", deviceId, srcIp);
    }
}
