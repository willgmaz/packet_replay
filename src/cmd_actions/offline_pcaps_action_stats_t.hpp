#pragma once

#include "traffic_replay.hpp"

namespace replay {
	
	struct offline_pcaps_action_stats_t
	{
	public:
		offline_pcaps_action_stats_t(): pcap_count(0){}

		bool do_action(const char* pcap_file)
		{
			offline_pcap_t pcap;
			pcap_count++;
			if (!pcap.open(pcap, pcap_file)) 
			{
				std::cout << pcap_count << ": corrupted pcap: " << pcap_file << std::endl;
				corrupted_pcaps.push_back(pcap_file);
				return false;
			}

			pcap_stat_t sta = pcap.dump_stats();
			std::cout << pcap_count << ": Pcap stats: " << pcap_file  << std::endl;
			std::cout << "   start_time: " << sta.start_time.tv_sec << std::endl;
			std::cout << "   end_time:   " << sta.end_time.tv_sec << std::endl;
			std::cout << "   pkts:       " << sta.count << std::endl;

			return true;
		}

		void dump_stats() 
		{
			std::cout << "Pcap stats: " << pcap_file << std::endl;
			std::cout << "  total pcaps:     " << pcap_count << std::endl;
			std::cout << "  corrupted pcaps: " << corrupted_pcaps.size() << std::endl;

			for (size_t i = 0; i < corrupted_pcaps.size(); i++) 
				std::cout << "  " << corrupted_pcaps[i] << std::endl;
		}

		uint32_t pcap_count;
		std::vector<std::string> corrupted_pcaps;
	};	
}