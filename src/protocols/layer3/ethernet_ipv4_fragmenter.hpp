#pragma once
#include <bittypes.h>
#include <protocols/layer2/ethernet2.hpp>
#include <protocols/layer3/ipv4.hpp>
#include <protocols/layer4/common.hpp>
#include <protocols/layer4/tcp.hpp>
#include <protocols/layer4/udp.hpp>
#include <endian/endianness.hpp>
#include <crypto/checksum.hpp>

namespace layer3 {
	namespace frag {

		/*
		Maximum Transmission Unit (MTU) is the maximum length of data that can be
		transmitted by a protocol in one instance. If we take the Ethernet interface
		as an example, the MTU size of an Ethernet interface is 1500 bytes by default,
		which excludes the Ethernet frame header and trailer. It means that the interface
		cannot carry any frame larger then 1500 bytes. If we look inside the frame,
		we have a 20 byte IP header + 20 byte TCP header, leaving a 1460 byte of the
		payload that can be transmitted in one frame.
		*/
		struct ethernet_ipv4_fragmenter
		{
			static const uint16_t mtu_default = 1500;

		public:
			static bool fragment(const u_char* data, uint32_t data_length, uint16_t offset = 0)
			{
				layer3::ipv4::ethernet_ipv4_header_t* ethip = layer3::ipv4::ethernet_ipv4_header_t::get_header(data, offset);
				return ethip->ip_header.packet_length > mtu_default;
			}

			static uint8_t do_fragment(pcap_t* dst_if, const u_char* data, uint32_t data_length, uint16_t offset = 0, bool first_packet_only = false)
			{
				layer3::ipv4::ethernet_ipv4_header_t* ethip = layer3::ipv4::ethernet_ipv4_header_t::get_header(data, offset);

				if (ethip->ip_header.packet_length <= mtu_default)
					return 0;

				if (ethip->ip_header.packet_length > data_length)
					return 0;

				uint32_t max_packet_size = mtu_default + ethip->eth_header.length;
				uint8_t* frag_packet = static_cast<uint8_t*>(malloc(max_packet_size));
				const u_char* frag_packet_data = static_cast<u_char*>(frag_packet);

				if (frag_packet == 0)
					return 0;

				uint16_t ip_hd_length = ethip->ip_header.get_length();
				uint16_t ip_payload_max = mtu_default - ip_hd_length;
				uint32_t ip_payload_length = ethip->ip_header.packet_length - ip_hd_length;

				uint16_t eth_ip_hd_length = ethip->header_length();
				uint8_t* current_data_offset = (uint8_t*)(data + eth_ip_hd_length);

				//eth + ip headers
				if (memcpy_s(frag_packet, mtu_default, data, eth_ip_hd_length) != 0)
					return 0;

				layer3::ipv4::ethernet_ipv4_header_t* fragment_ethip = layer3::ipv4::ethernet_ipv4_header_t::get_header(frag_packet, 0);
				frag_packet += eth_ip_hd_length;
				uint16_t frag_packet_max_data = max_packet_size - eth_ip_hd_length;

				uint8_t ret = 0;
				uint32_t ip_fragment_offset = 0;

				while (ip_payload_length != 0)
				{
					if (ip_payload_length > ip_payload_max)
					{
						if (memcpy_s(frag_packet, frag_packet_max_data, current_data_offset, ip_payload_max) != 0)
						{
							ret = 0;
							break;
						}

						fragment_ethip->ip_header.packet_length = ip_hd_length + ip_payload_max;

						//send only the first packet.
						//this is a HACK!!. Done becuase sever side rules are not
						//triggering on fragmented packets :-(
						if (!first_packet_only)
							fragment_ethip->ip_header.set_fragment_offset(ip_fragment_offset);
						else
							fragment_ethip->ip_header.clear_more_fragments();

						fragment_ethip->ip_header.fix_header_checksum();

						//If hacking frag then we need fix TCP check sum
						if (first_packet_only) 
						{
							if (fragment_ethip->ip_header.upper_layer_type() == layer4::types_t::enums::tcp)
								layer4::tcp::eth_ipv4_tcp_header_t::fix_checksum(frag_packet_data);
							else if (fragment_ethip->ip_header.upper_layer_type() == layer4::types_t::enums::udp)
								layer4::udp::udp_eth_ipv4_packet_t::fix_checksum(frag_packet_data);
						}				

						ip_payload_length -= ip_payload_max;
						current_data_offset += ip_payload_max;
						ip_fragment_offset += ip_payload_max;					

						if (pcap_sendpacket(dst_if, frag_packet_data,
							fragment_ethip->ip_header.packet_length + ethip->eth_header.length) < 0)
						{
							ret = 0;
							break;
						}

						ret++;

						if (first_packet_only)
							break;
					}
					else
					{
						if (memcpy_s(frag_packet, frag_packet_max_data, current_data_offset, ip_payload_length) != 0)
						{
							ret = 0;
							break;
						}

						fragment_ethip->ip_header.packet_length = ip_hd_length + ip_payload_length;
						fragment_ethip->ip_header.set_fragment_offset(ip_fragment_offset);
						fragment_ethip->ip_header.clear_more_fragments();
						
						fragment_ethip->ip_header.fix_header_checksum();					

						ip_payload_length = 0;

						if (pcap_sendpacket(dst_if, frag_packet_data,
							fragment_ethip->ip_header.packet_length + ethip->eth_header.length) < 0)
						{
							ret = 0;
							break;
						}

						ret++;
					}
				}

				free((void*)frag_packet_data);
				return ret;
			}
		};
	}
}