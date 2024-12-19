#pragma once

#include "traffic_replay.hpp"
#include <cmd_actions/pcap_devs_action_getif_t.hpp>

namespace replay {
	
	struct offline_pcaps_action_replay_t
	{
	public:
		offline_pcaps_action_replay_t() :
			pcap_count(0),
			m_failed_packet_count(0),
			m_packet_count(0),
			m_replayed_packet_count(0),
			m_l2_non_supported_packet_count(0)
		{}

		bool init(const char* src, const char* dst, bool ip_if)
		{
			if (ip_if)
			{
				pcap_devs_t devs_1;
				pcap_devs_action_getif_t src_if(src);
				devs_1.get_ifs(src_if);

				pcap_devs_t devs_2;
				pcap_devs_action_getif_t dst_if(dst);
				devs_2.get_ifs(dst_if);

				return m_rsplit.init(src_if.m_id.c_str(), dst_if.m_id.c_str());
			}
			
			return m_rsplit.init(src, dst);
		}

		bool init(const char* si, const char* di, const char* sip, const char* dip)
		{
			return m_rsplit.init(si, di, sip, dip);
		}

		bool do_action(const char* pcap_file, bool clean_stats = true)
		{
			pcap_count++;
			
			offline_pcap_t pcap;
			if (!pcap.open(pcap, pcap_file)) 
			{
				corrupted_pcaps.push_back(pcap_file);
				return false;
			}

			pcap_layer2_split_replay_t::play_back(m_rsplit, pcap);

			m_replayed_packet_count += m_rsplit.get_replayed_packet_count();
			m_packet_count += m_rsplit.get_packet_count();

			if (m_rsplit.has_bad_ptks())
			{
				if (m_rsplit.get_l2_non_supported_packet_count() > 0)
					l2_non_supported_replays_pcaps.push_back(pcap_file);

				if (m_rsplit.get_failed_packet_count() > 0)
					failed_replays_pcaps.push_back(pcap_file);

				m_failed_packet_count += m_rsplit.get_failed_packet_count();
				m_l2_non_supported_packet_count += m_rsplit.get_l2_non_supported_packet_count();
			}

			if(clean_stats)
				m_rsplit.clean_stats();

			return true;
		}		

		bool errors() {
			return m_failed_packet_count > 0 || m_l2_non_supported_packet_count > 0 || corrupted_pcaps.size() > 0;
		}

		void dump_stats(std::ostream& strm)
		{
			strm << "Pcap stats: " << std::endl;
			strm << "  Total pcaps:               " << pcap_count << std::endl;
			strm << "  Corrupted pcaps:           " << corrupted_pcaps.size() << std::endl;
			strm << "  Total packets:             " << m_packet_count << std::endl;
			strm << "  Replayed packets:          " << m_replayed_packet_count << std::endl;
			strm << "  Pcaps with failed packets: " << failed_replays_pcaps.size() << std::endl;
			strm << "  L2 non-suported packets:   " << m_l2_non_supported_packet_count << std::endl;
			strm << "  Failed packet count:       " << m_failed_packet_count << std::endl;		

			if (corrupted_pcaps.size() > 0)
			{
				strm << "  Corrupted pcaps list :" << std::endl;
				for (size_t i = 0; i < corrupted_pcaps.size(); i++)
					strm << "   " << corrupted_pcaps[i] << std::endl;
			}

			if (l2_non_supported_replays_pcaps.size() > 0)
			{
				strm << "  Pcaps with L2 layer non-suppored :" << std::endl;
				for (size_t i = 0; i < l2_non_supported_replays_pcaps.size(); i++)
					strm << "    " << l2_non_supported_replays_pcaps[i] << std::endl;
			}
			
			if (failed_replays_pcaps.size() > 0)
			{
				strm << "  Pcaps with failed packets list :" << std::endl;
				for (size_t i = 0; i < failed_replays_pcaps.size(); i++)
					strm << "    " << failed_replays_pcaps[i] << std::endl;
			}
		}
		
		pcap_layer2_split_replay_t m_rsplit;
		uint32_t pcap_count;
		std::string m_src_ifname;
		std::string m_dst_ifname;
		bool m_ip_if;
		std::vector<std::string> corrupted_pcaps;

		uint64_t m_failed_packet_count;
		uint64_t m_packet_count;
		uint64_t m_l2_non_supported_packet_count;
		uint64_t m_replayed_packet_count;
		std::vector<std::string> failed_replays_pcaps;
		std::vector<std::string> l2_non_supported_replays_pcaps;
	};	
}