#pragma once
#include "bittypes.h"
#include "pcap.h"

namespace layer3 {

	struct types_t {
		enum enums: uint16_t {
			pup                       = 0x0200,
			ipv4                      = 0x0800,
			arp                       = 0x0806,
			rarp                      = 0x8035,
			vlan_tagging_8021q        = 0x8100,
			eap_authentication_8021x  = 0x888e,
			mpls	                  = 0x8847,
			test_interfaces	          = 0x9000,
			ipv6	                  = 0x86DD
		};
	};	

}