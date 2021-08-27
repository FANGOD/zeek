module PacketAnalyzer::TEREDO;

export {
        ## Default analyzer
        const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_IP &redef;
}

const teredo_ports = { 3544/udp };
redef likely_server_ports += { teredo_ports };

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_protocol_detection(PacketAnalyzer::ANALYZER_UDP, PacketAnalyzer::ANALYZER_TEREDO);

	for ( p in teredo_ports )
		PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_UDP, port_to_count(p), PacketAnalyzer::ANALYZER_TEREDO);
	}
