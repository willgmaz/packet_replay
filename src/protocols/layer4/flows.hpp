#pragma once
#include <stdint.h>
#include <map>
#include <set>

namespace layer4 {
	namespace tcp {		

		struct flow_tracker_t
		{
		public:
			typedef std::map<uint64_t, uint64_t> dst_map_t;
			typedef std::map<uint64_t, dst_map_t> flows_t;

		public:
			bool add(uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport)
			{
				m_data[get_ipport(sip, sport)][get_ipport(dip, dport)] = 0;
			}

			bool is_src_to_dst(uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport)
			{
				return update_port(get_ipport(sip, sport), get_ipport(dip, dport));
			}

			bool is_dst_to_src(uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport)
			{
				return update_port(get_ipport(dip, dport), get_ipport(sip, sport));
			}

			void clear() { m_data.clear(); }


		private:
			inline bool update_port(uint64_t src, uint64_t dst)
			{
				flows_t::iterator source = m_data.find(src);
				if (source == m_data.end())
					return false;

				return source->second.find(dst) != source->second.end();
			}		

			inline uint64_t get_ipport(uint32_t ip, uint16_t port) 
			{
				uint64_t source = ip;
				source << 32;
				source | port;
				return  source;
			}
			
		private:
			flows_t m_data;
		}; 
	}	
}