#pragma once

#include <iostream>
#include <string>
#include <set>
#include <fstream>

#include "pcap.h"

#include <protocols/layer2/common.hpp>
#include <protocols/layer2/ethernet2.hpp>
#include <protocols/layer3/ipv4.hpp>
#include <protocols/layer3/ethernet_ipv4_fragmenter.hpp>
#include <protocols/layer3/common.hpp>
#include <protocols/layer4/tcp.hpp>
#include <protocols/layer4/udp.hpp>
#include <traffic_replay.hpp>
#include <windows/windows.hpp>

namespace replay {

	class udp_payload
	{	
	public:
		static void extract(udp_payload& pcaplive, const offline_pcap_t& pcap) { pcap.get_packets(pcaplive); }

	public:
		udp_payload(){}

		~udp_payload(){}

		void init(const char* out_folder)
		{
			
		}		

		bool do_action(pcap_pkthdr& pk_header, const u_char *data, layer2::types_t::enums& data_link_type)
		{
			if (data == 0)
				return false;

			m_pkt_count++;

			if (data_link_type == layer2::types_t::ethernet_10mb)
			{
				layer2::ethernet2_header_t* eth_header = static_cast<layer2::ethernet2_header_t*>((void*)data);

				if (eth_header->get_payload_type() != layer3::types_t::ipv4)
					return false;

				layer3::ipv4::ethernet_ipv4_header_t* eth_ip_header =
					layer3::ipv4::ethernet_ipv4_header_t::get_header(data);

				//fix pcap IP packet length.
				//some times "packet_length" is 0 becuase "TCP segmentation offload". We try to fix it here acording to
				//packet data size.
				if (eth_ip_header->ip_header.packet_length == 0)
					eth_ip_header->ip_header.packet_length = pk_header.caplen - eth_ip_header->eth_header.length;

				//somes time IP packet length is greater than pcap packet size.
				//this happens when "Packet size limited during capture"
				if (eth_ip_header->ip_header.packet_length > pk_header.caplen - eth_ip_header->eth_header.length)
					eth_ip_header->ip_header.packet_length = pk_header.caplen - eth_ip_header->eth_header.length;

				//pcaps can have Ethernet padding bytes at the end. pcap lib will fail to replay them if
				//the total size is greater than the mtu. Here we are calculating the "util" pcayload to replay.
				uint16_t full_packet_len = eth_ip_header->eth_header.length + eth_ip_header->ip_header.packet_length;

				if (eth_ip_header->ip_header.upper_layer_type() == layer4::types_t::enums::udp) 
				{
					m_udp_pkt_count++;

					layer4::udp::udp_eth_ipv4_packet_t hd;
					if (!layer4::udp::udp_eth_ipv4_packet_t::parse(data, &hd))
						return false;

					char* ppayl = (char*)&data[hd.get_payload_offset()];
					std::ofstream payload("1.raw", std::ofstream::binary);
					payload.write(ppayl, hd.upd->len);
				}
			}

			return false;
		}			

	private:
		uint64_t m_pkt_count;
		uint64_t m_udp_pkt_count;
	};
}