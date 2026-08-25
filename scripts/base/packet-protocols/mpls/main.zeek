module PacketAnalyzer::MPLS;

export {
	## Default analyzer
	const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_IP &redef;
}

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x8847, PacketAnalyzer::ANALYZER_MPLS);
	}
