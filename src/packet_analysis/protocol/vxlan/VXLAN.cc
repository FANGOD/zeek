// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/vxlan/VXLAN.h"
#include "zeek/packet_analysis/protocol/vxlan/events.bif.h"
#include "zeek/packet_analysis/protocol/iptunnel/IPTunnel.h"

using namespace zeek::packet_analysis::VXLAN;

VXLAN_Analyzer::VXLAN_Analyzer()
	: zeek::packet_analysis::Analyzer("VXLAN")
	{
	}

bool VXLAN_Analyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	if ( packet->encap &&
	     packet->encap->Depth() >= BifConst::Tunnel::max_depth )
		{
		Weird("exceeded_tunnel_max_depth", packet);
		return false;
		}

	constexpr uint16_t hdr_size = 8;

	if ( hdr_size > len )
		{
		// TODO
		// ProtocolViolation("VXLAN header truncation", (const char*) data, len);
		Weird("truncated_vxlan", packet);
		return false;
		}

	if ( (data[0] & 0x08) == 0 )
		{
		// TODO
		//ProtocolViolation("VXLAN 'I' flag not set", (const char*) data, len);
		return false;
		}

	int vni = (data[4] << 16) + (data[5] << 8) + (data[6] << 0);

	len -= hdr_size;
	data += hdr_size;

	Packet inner_packet;
	int encap_index = 0;
	packet_analysis::IPTunnel::build_inner_packet(
		&inner_packet, packet, -1, &encap_index,
		nullptr, len, data, DLT_RAW, BifEnum::Tunnel::VXLAN,
		GetAnalyzerTag());

	bool fwd_ret_val = true;
	if ( len > hdr_size )
		fwd_ret_val = ForwardPacket(len, data, &inner_packet);

	if ( fwd_ret_val && vxlan_packet && packet->session )
		{
		EncapsulatingConn* ec = inner_packet.encap->At(encap_index);
		if ( ec && ec->ip_hdr )
			inner_packet.session->EnqueueEvent(vxlan_packet, nullptr, packet->session->GetVal(),
			                                   ec->ip_hdr->ToPktHdrVal(), val_mgr->Count(vni));

		// TODO protocol confirmation
		}

	return fwd_ret_val;
	}
