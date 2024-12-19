#pragma once

#include <string>
#include "traffic_replay.hpp"

namespace replay {

	struct pcap_devs_action_getif_t
	{
	public:
		pcap_devs_action_getif_t(const char* ip) :m_n(ip) {}

		bool do_action(pcap_if_t* ifdev = 0)
		{
			if (ifdev == 0)
				return false;

			if (ifdev->addresses != 0)
			{
				for (pcap_addr* address = ifdev->addresses; address != 0; address = address->next)
				{
					if (address->addr == 0)
						continue;

					if (address->addr->sa_data == 0)
						continue;

					//ip
					if (address->addr->sa_family == AF_INET)
					{
						std::string ip_str(inet_ntoa(((struct sockaddr_in*)address->addr)->sin_addr));

						if (ip_str == m_n) {
							m_id = ifdev->name;
							return true;
						}

						continue;
					}
				}
			}

			return false;
		}

		std::string m_id;
		std::string m_n;
	};
}