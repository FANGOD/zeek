#pragma once

namespace zeek::packet_analysis::teredo::detail {

class TeredoEncapsulation {
public:
	explicit TeredoEncapsulation(const Teredo_Analyzer* ta)
		: inner_ip(nullptr), origin_indication(nullptr), auth(nullptr), analyzer(ta)
		{}

	/**
	 * Returns whether input data parsed as a valid Teredo encapsulation type.
	 * If it was valid, the len argument is decremented appropriately.
	 */
	bool Parse(const u_char* data, int& len)
		{ return DoParse(data, len, false, false); }

	const u_char* InnerIP() const
		{ return inner_ip; }

	const u_char* OriginIndication() const
		{ return origin_indication; }

	const u_char* Authentication() const
		{ return auth; }

	RecordValPtr BuildVal(const std::shared_ptr<IP_Hdr>& inner) const;

protected:
	bool DoParse(const u_char* data, int& len, bool found_orig, bool found_au);

	void Weird(const char* name) const
		{ analyzer->Weird(name); }

	const u_char* inner_ip;
	const u_char* origin_indication;
	const u_char* auth;
	const Teredo_Analyzer* analyzer;
};

} // zeek::packet_analysis::teredo::detail
