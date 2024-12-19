#pragma once
#include <stdint.h>
#include <endian/endianness.hpp>
#include <crypto/checksum.hpp>

namespace layer4 {
	namespace tcp {	

		#pragma pack(push)
		#pragma pack(1)
		struct tcp_header_t
		{
			endian::int16_bigendia_t port_src;
			endian::int16_bigendia_t port_dst;
			endian::int32_bigendia_t seq_no;
			endian::int32_bigendia_t ack_no;
			endian::int16_bigendia_t flags;
			endian::int16_bigendia_t window;
			endian::int16_bigendia_t check_sum;
			endian::int16_bigendia_t urgent;

			static tcp_header_t* get_header(const u_char* data, uint16_t offset)
			{
				return static_cast<tcp_header_t*>((void*)&data[offset]);
			}						
		}; 
		#pragma pack(pop)

		struct eth_ipv4_tcp_header_t
		{
			layer3::ipv4::ethernet_ipv4_header_t* eth_ipv4;
			tcp_header_t* tcp;

		public:
			static bool get_eth_ipv4_tcp_header(const u_char* data, eth_ipv4_tcp_header_t* hd)
			{
				layer2::ethernet2_header_t* eth_header = static_cast<layer2::ethernet2_header_t*>((void*)data);

				if (eth_header->get_payload_type() != layer3::types_t::ipv4)
					return false;

				hd->eth_ipv4 = layer3::ipv4::ethernet_ipv4_header_t::get_header(data);

				if (hd->eth_ipv4->ip_header.upper_layer_type() != layer4::types_t::enums::tcp)
					return false;

				hd->tcp = layer4::tcp::tcp_header_t::get_header(data, hd->eth_ipv4->get_abs_upper_offset());
				return true;
			}

			static bool fix_checksum(const u_char* data)
			{
				eth_ipv4_tcp_header_t hd;
				if(!get_eth_ipv4_tcp_header(data, &hd))
					return false;

				hd.tcp->check_sum = 0;

				uint32_t sum = crypto::checksum_t::sum16_bits(
					static_cast<uint8_t*>((void*)&(hd.eth_ipv4->ip_header.source_address)), 0, 8);

				uint16_t len = hd.eth_ipv4->ip_header.payload_length();

				sum += IPPROTO_TCP + len;
				sum += crypto::checksum_t::sum16_bits(
					static_cast<uint8_t*>((void*)&(data[hd.eth_ipv4->get_abs_upper_offset()])), 0, len);

				hd.tcp->check_sum = crypto::checksum_t::sum16bits_to_checksum(sum);

				return true;
			}			
		};
	}	
}