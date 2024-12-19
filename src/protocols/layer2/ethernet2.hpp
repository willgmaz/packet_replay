#pragma once
#include "bittypes.h"
#include <protocols/layer3/common.hpp>
#include <endian/endianness.hpp>

namespace layer2 {

	const uint8_t ethernet2_mac_length = 6;
	const uint64_t ethernet2_mac_broadcast = 0x0000ffffffffffff;
	    
	#pragma pack(push)
	#pragma pack(1)
	struct ethernet2_header_t 
	{
	public:
		static const uint8_t length = 14;

	public:
		static uint64_t to_uint64_t(uint8_t* dst_mac)
		{
			if(dst_mac == 0)
				return 0;

			return	uint64_t(dst_mac[0]) << 40 |
				uint64_t(dst_mac[1]) << 32 |
				uint64_t(dst_mac[2]) << 24 |
				uint64_t(dst_mac[3]) << 16 |
				uint64_t(dst_mac[4]) << 8 |
				uint64_t(dst_mac[5]);
		}

	public:
		uint64_t get_src(){return to_uint64_t(src_mac);}

		uint64_t get_dst(){return to_uint64_t(dst_mac);}

		bool src_is_broadcast(){return get_src() == ethernet2_mac_broadcast;}

		bool dst_is_broadcast(){return get_dst() == ethernet2_mac_broadcast;}

		void update_src(const uint64_t& val){update_mac(src_mac, val);}

		void update_dst(const uint64_t& val){update_mac(dst_mac, val);}

		layer3::types_t::enums get_payload_type(){return static_cast<layer3::types_t::enums>((uint16_t)payload_type);}
	
	private:
		void update_mac(uint8_t* mac, const uint64_t& val)
		{
			mac[5] = static_cast<const uint8_t*>((void*)&val)[0];	
			mac[4] = static_cast<const uint8_t*>((void*)&val)[1];	
			mac[3] = static_cast<const uint8_t*>((void*)&val)[2];	
			mac[2] = static_cast<const uint8_t*>((void*)&val)[3];	
			mac[1] = static_cast<const uint8_t*>((void*)&val)[4];	
			mac[0] = static_cast<const uint8_t*>((void*)&val)[5];	
		}

	public:
		uint8_t dst_mac[ethernet2_mac_length];
		uint8_t src_mac[ethernet2_mac_length];
		endian::uint16_bigendia_t payload_type;
	}; 
	#pragma pack(pop)
}