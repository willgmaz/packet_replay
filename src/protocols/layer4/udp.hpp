#pragma once
#include <stdint.h>
#include <crypto/checksum.hpp>
#include <protocols/layer3/ipv4.hpp>

namespace layer4 {
	namespace udp {	

		#pragma pack(push)
		#pragma pack(1)
		struct udp_header_t
		{
			uint16_t sport;    // soure port
			uint16_t dport;    // destination port
			uint16_t len;      // payload length
			uint16_t sum;      // checksum
		
		public:
			static udp_header_t* parse(const u_char* data, uint16_t offset)
			{
				return static_cast<udp_header_t*>((void*)&data[offset]);
			}						
		}; 
		#pragma pack(pop)

		struct udp_eth_ipv4_packet_t
		{
			layer2::ethernet2_header_t* eth;
			layer3::ipv4::ipv4_header_t* ipv4;
			udp_header_t* upd;

		public:			
			static bool parse(const u_char* data, udp_eth_ipv4_packet_t* pkt)
			{
				pkt->eth = static_cast<layer2::ethernet2_header_t*>((void*)data);

				if (pkt->eth->get_payload_type() != layer3::types_t::ipv4)
					return false;

				pkt->ipv4 = layer3::ipv4::ipv4_header_t::parse(data, layer2::ethernet2_header_t::length);

				if (pkt->ipv4->upper_layer_type() != layer4::types_t::enums::udp)
					return false;

				pkt->upd = udp_header_t::parse(data, pkt->get_abs_upper_offset());

				return true;
			}

			static bool fix_checksum(const u_char* data)
			{
				udp_eth_ipv4_packet_t hd;
				if(!parse(data, &hd))
					return false;

				hd.upd->sum = 0;

				uint32_t sum = crypto::checksum_t::sum16_bits(
					static_cast<uint8_t*>((void*)&(hd.ipv4->source_address)), 0, 8);

				uint16_t len = hd.ipv4->payload_length();

				sum += IPPROTO_UDP + len;
				sum += crypto::checksum_t::sum16_bits(
					static_cast<uint8_t*>((void*)&(data[hd.get_abs_upper_offset()])), 0, len);

				hd.upd->sum = ntohs(crypto::checksum_t::sum16bits_to_checksum(sum));

				return true;
			}

		public:
			uint16_t get_payload_offset() { return get_abs_upper_offset() + sizeof(udp_header_t); }

		private:
			uint16_t get_abs_upper_offset() { return ipv4->get_length() + layer2::ethernet2_header_t::length; }
			
		};
	}	
}