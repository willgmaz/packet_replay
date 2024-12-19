#pragma once
#include <stdint.h>

namespace layer4 {
	struct types_t {
		enum enums : uint8_t {
			icmp = 0x01,    //1  0x01  ICMP   Internet Control Message Protocol
			tcp = 0x06,    //6  0x06  TCP    Transmission Control Protocol	
			udp = 0x11     //17 0x11  UDP    User Datagram Protocol
		};
	};
}