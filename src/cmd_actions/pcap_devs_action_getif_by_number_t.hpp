#pragma once

#include <string>
#include "traffic_replay.hpp"

namespace replay {

	struct pcap_devs_action_getif_by_number_t
	{
	public:
		pcap_devs_action_getif_by_number_t(uint8_t n) :m_n(n), m_count(0){}

		bool do_action(pcap_if_t* ifdev = 0)
		{
			if (ifdev == 0)
				return false;

			if (m_n == m_count) {
				m_id = ifdev->name;
				return true;
			}

			m_count++;
			return false;			
		}

		std::string m_id;
		uint8_t m_n;
		uint8_t m_count;
	};
}