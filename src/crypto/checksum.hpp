#pragma once 
#include "bittypes.h"

namespace crypto
{
	struct checksum_t
	{	
		 static uint16_t calc(uint16_t *data, int len)
		 {
           long sum = 0;  /* assume 32 bit long, 16 bit short */
           while(len > 1)
		   {
             sum += *data++;
             if(sum & 0x80000000)   /* if high order bit set, fold */
               sum = (sum & 0xFFFF) + (sum >> 16);
             
			 len -= 2;
           }

           if(len)       /* take care of left over byte */
             sum += *data;
          
           while(sum >> 16)
             sum = (sum & 0xFFFF) + (sum >> 16);

           return static_cast<uint16_t>(~sum);
         }


		 /// Sums bytes in a buffer as 16 bits big endian values.
		 /// If the number of bytes is odd then a 0x00 value is assumed after the last byte
		 static uint32_t sum16_bits(uint8_t* buffer, int offset, int length)
		 {
			 long sum = 0;
			 int i = offset;
			 for (; i + 1 < (length + offset); i += 2)
				 sum += ((uint16_t)(((buffer[i] << 8) & 0xFF00) + (buffer[i + 1] & 0xFF)));

			 if (length + offset == i + 1)
				 sum += ((uint16_t)(((buffer[i] << 8) & 0xFF00))); //last byte 0

			 return sum;
		 }

		 static uint16_t sum16bits_to_checksum(uint32_t sum)
		 {
			 while ((sum >> 16) != 0)
				 sum = (sum & 0xFFFF) + (sum >> 16);

			 sum = ~sum;
			 return (uint16_t)sum;
		 }
	};
}

