module PacketAnalyzer::VXLAN;

export {
	# There's no indicator in the VXLAN packet header format about what the next protocol
	# in the chain is. All of the documentation just lists Ethernet, so default to that.
        const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_ETHERNET &redef;

	## The set of UDP ports used for VXLAN traffic.  Traffic using this
	## UDP destination port will attempt to be decapsulated.  Note that if
	## if you customize this, you may still want to manually ensure that
	## :zeek:see:`likely_server_ports` also gets populated accordingly.
	const vxlan_ports: set[port] = { 4789/udp } &redef;
}

redef likely_server_ports += { vxlan_ports };

event zeek_init() &priority=20
	{
	for ( p in vxlan_ports )
		PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_UDP, port_to_count(p), PacketAnalyzer::ANALYZER_VXLAN);
	}
