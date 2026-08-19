"""
Ryu/os-ken SDN Controller for Zero Trust Enforcement.

This is a standalone OpenFlow 1.3 controller that:
1. Acts as a learning switch (L2 forwarding)
2. Collects per-flow statistics
3. Applies trust-based blocking/allowing
4. Shares state via a JSON file for the REST API/policy engine to read

Run with: sudo ./venv/bin/python run_controller.py
"""

import json
import time
import os
import threading
from collections import defaultdict

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ether_types, ipv4
from os_ken.lib import hub

# Shared state file for communication with REST API / policy engine
STATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'data')
STATE_FILE = os.path.join(STATE_DIR, 'controller_state.json')
COMMANDS_FILE = os.path.join(STATE_DIR, 'controller_commands.json')

os.makedirs(STATE_DIR, exist_ok=True)


class TrustController(app_manager.OSKenApp):
    """
    OpenFlow 1.3 controller with trust-based enforcement.

    Communicates with the policy engine via shared JSON files:
    - Writes: controller_state.json (flow stats, current scores)
    - Reads: controller_commands.json (trust score updates, block/unblock)
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    STATS_INTERVAL = 5

    def __init__(self, *args, **kwargs):
        super(TrustController, self).__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.datapaths = {}
        self.flow_stats = defaultdict(lambda: defaultdict(dict))

        self.trust_scores = {
            '10.0.0.1': 100.0,
            '10.0.0.2': 100.0,
            '10.0.0.3': 100.0,
            '10.0.0.4': 100.0,
        }
        self.enforcement_actions = defaultdict(lambda: 'allow')
        self.blocked_hosts = set()

        # Start background threads
        self.monitor_thread = hub.spawn(self._monitor)
        self.state_writer_thread = hub.spawn(self._state_writer)
        self.command_reader_thread = hub.spawn(self._command_reader)

        self.logger.info("TrustController initialized")

    # ==================== Background Tasks ====================

    def _monitor(self):
        """Periodically request flow stats."""
        while True:
            for dpid, dp in list(self.datapaths.items()):
                self._request_stats(dp)
            hub.sleep(self.STATS_INTERVAL)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def _state_writer(self):
        """Periodically write state to JSON for the REST API."""
        while True:
            try:
                state = {
                    'timestamp': time.time(),
                    'trust_scores': dict(self.trust_scores),
                    'enforcement_actions': dict(self.enforcement_actions),
                    'blocked_hosts': list(self.blocked_hosts),
                    'flow_stats': self._serialize_flow_stats(),
                    'switch_count': len(self.datapaths),
                }
                with open(STATE_FILE, 'w') as f:
                    json.dump(state, f, indent=2, default=str)
            except Exception as e:
                self.logger.error(f"State write error: {e}")
            hub.sleep(2)

    def _command_reader(self):
        """Read commands from the policy engine."""
        while True:
            try:
                if os.path.exists(COMMANDS_FILE):
                    with open(COMMANDS_FILE, 'r') as f:
                        commands = json.load(f)

                    if commands:
                        for cmd in commands:
                            self._process_command(cmd)
                        # Clear processed commands
                        with open(COMMANDS_FILE, 'w') as f:
                            json.dump([], f)
            except (json.JSONDecodeError, IOError):
                pass
            except Exception as e:
                self.logger.error(f"Command read error: {e}")
            hub.sleep(1)

    def _process_command(self, cmd):
        """Process a command from the policy engine."""
        cmd_type = cmd.get('type', '')
        ip = cmd.get('ip', '')

        if cmd_type == 'update_score':
            score = float(cmd.get('score', 100))
            self._update_trust_score(ip, score)
        elif cmd_type == 'block':
            self._update_trust_score(ip, 0)
        elif cmd_type == 'unblock':
            self._update_trust_score(ip, 100)

    def _serialize_flow_stats(self):
        result = {}
        for dpid, flows in self.flow_stats.items():
            result[str(dpid)] = {}
            for flow_key, stats in flows.items():
                key_str = f"{flow_key[0]}->{flow_key[1]}"
                result[str(dpid)][key_str] = dict(stats)
        return result

    # ==================== Trust Management ====================

    def _update_trust_score(self, ip, score):
        old_score = self.trust_scores.get(ip, 100.0)
        self.trust_scores[ip] = score

        if score >= 80:
            action = 'allow'
        elif score >= 50:
            action = 'rate_limit'
        elif score >= 20:
            action = 'restrict'
        else:
            action = 'block'

        old_action = self.enforcement_actions.get(ip, 'allow')
        self.enforcement_actions[ip] = action

        if action == 'block' and ip not in self.blocked_hosts:
            self.blocked_hosts.add(ip)
            self._enforce_block(ip)
        elif action != 'block' and ip in self.blocked_hosts:
            self.blocked_hosts.discard(ip)
            self._enforce_unblock(ip)

        self.logger.info(
            f"Trust: {ip} {old_score:.1f}->{score:.1f} [{old_action}->{action}]"
        )

    def _enforce_block(self, ip):
        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip
            )
            self._add_flow(datapath, 100, match, [], hard_timeout=300)
            self.logger.warning(f"BLOCKED: {ip}")

    def _enforce_unblock(self, ip):
        for dpid, datapath in self.datapaths.items():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip
            )
            mod = parser.OFPFlowMod(
                datapath=datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                match=match
            )
            datapath.send_msg(mod)
            self.logger.info(f"UNBLOCKED: {ip}")

    # ==================== OpenFlow Event Handlers ====================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info(f"Switch connected: dpid={datapath.id}")

        # Table-miss: send to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER
        )]
        self._add_flow(datapath, 0, match, actions)

        self.mac_to_port.setdefault(datapath.id, {})
        self.datapaths[datapath.id] = datapath

    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions
        )]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority,
            match=match, instructions=inst,
            idle_timeout=idle_timeout, hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        for stat in ev.msg.body:
            if 'ipv4_src' in stat.match and 'ipv4_dst' in stat.match:
                src_ip = stat.match['ipv4_src']
                dst_ip = stat.match['ipv4_dst']
                self.flow_stats[dpid][(src_ip, dst_ip)] = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'packet_count': stat.packet_count,
                    'byte_count': stat.byte_count,
                    'duration_sec': stat.duration_sec,
                    'first_seen': time.time() - stat.duration_sec,
                    'last_seen': time.time(),
                }

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst_mac = eth.dst
        src_mac = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        # Trust enforcement check
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst

            # Update flow stats
            flow_key = (src_ip, dst_ip)
            if flow_key not in self.flow_stats[dpid]:
                self.flow_stats[dpid][flow_key] = {
                    'packet_count': 0, 'byte_count': 0,
                    'first_seen': time.time(), 'last_seen': time.time(),
                    'src_ip': src_ip, 'dst_ip': dst_ip,
                }
            s = self.flow_stats[dpid][flow_key]
            s['packet_count'] += 1
            s['byte_count'] += len(msg.data)
            s['last_seen'] = time.time()

            action = self.enforcement_actions.get(src_ip, 'allow')
            if action == 'block' or src_ip in self.blocked_hosts:
                self.logger.warning(f"DROP: {src_ip} (score={self.trust_scores.get(src_ip)})")
                return

            if action == 'restrict' and dst_ip != '10.0.0.3':
                return

        # L2 forwarding
        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            if ip_pkt:
                match = parser.OFPMatch(
                    in_port=in_port, eth_dst=dst_mac, eth_src=src_mac,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst
                )
            else:
                match = parser.OFPMatch(
                    in_port=in_port, eth_dst=dst_mac, eth_src=src_mac
                )
            self._add_flow(datapath, 1, match, actions, idle_timeout=30)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data
        )
        datapath.send_msg(out)
