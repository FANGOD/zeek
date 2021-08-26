// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/ayiya/AYIYA.h"
#include "zeek/packet_analysis/protocol/iptunnel/IPTunnel.h"

using namespace zeek::packet_analysis::AYIYA;

AYIYAAnalyzer::AYIYAAnalyzer()
	: zeek::packet_analysis::Analyzer("AYIYA")
	{
	}

bool AYIYAAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	if ( ! BifConst::Tunnel::enable_ayiya )
		return false;

	if ( packet->encap &&
	     packet->encap->Depth() >= BifConst::Tunnel::max_depth )
		{
		Weird("exceeded_tunnel_max_depth", packet);
		return false;
		}

	// This will be expanded based on the header data, but it has to be at least
	// this long.
	size_t hdr_size = 8;

	if ( hdr_size > len )
		{
		Weird("truncated_ayiya", packet);
		return false;
		}

	uint8_t identity_len = 1 << (data[0] >> 4);
	uint8_t signature_len = (data[1] >> 4) * 4;
	hdr_size += identity_len + signature_len;

	// Double-check this one now that we know the actual full length of the header.
	if ( hdr_size > len )
		{
		Weird("truncated_ayiya", packet);
		return false;
		}

	uint8_t op_code = data[2] & 0x0F;

	// Check that op_code is the "forward" command. Everything else is ignored.
	// This isn't an error, it's just the end of our parsing.
	if ( op_code != 1 )
		return true;

	uint8_t next_header = data[3];

	// AYIYA can really hold anything, why do we limit the next header to IP only? This
	// really should let the forwarding code fail out instead.
	if ( next_header != IPPROTO_IPV4 && next_header != IPPROTO_IPV6 )
		{
		Weird("ayiya_tunnel_non_ip", packet);
		return false;
		}

	len -= hdr_size;
	data += hdr_size;

	Packet inner_packet;
	int encap_index = 0;
	packet_analysis::IPTunnel::build_inner_packet(
		&inner_packet, packet, next_header, &encap_index,
		nullptr, len, data, DLT_RAW, BifEnum::Tunnel::AYIYA,
		GetAnalyzerTag());

	// Skip the header and pass on to the next analyzer. It's possible for AYIYA to
	// just be a header and nothing after it, so check for that case.
	if ( len > hdr_size )
		return ForwardPacket(len, data, &inner_packet, next_header);

	return true;
	}

bool AYIYAAnalyzer::DetectProtocol(size_t len, const uint8_t* data, Packet* packet)
	{
	if ( ! BifConst::Tunnel::enable_ayiya )
		return false;

	// These magic numbers are based on the old DPD entry, which was based on... something?
	return len >= 3 && data[1] == 0x52 && data[2] == 0x11;
	}
