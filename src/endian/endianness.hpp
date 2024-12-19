#pragma once 
#include "bittypes.h"

namespace endian
{
	
	/*
				Data Types of Fixed Endianness

		When communicating between different processors using fixed-format
		binary messages, it's helpful to use a common header file to
		describe the messages in the protocol.  The problem comes when the
		processors are of differing endianness.

		The following templates support declaring multi-byte objects whose
		byte-order in memory is identical on all processors.  If the desired
		byte order matches the processor's endianness, simple loads and
		stores are used to access the objects.  On the other hand, if the
		desired order is opposite the processor's natural byte order, the
		values are byte swapped when creating the objects and when
		converting back to normal types.

		Use these templates to define structures for the protocol messages,
		then simply read and write the fields as usual.  Byte swapping will
		occur automatically if needed when the fields in the objects are
		read or written.

	*/


	/* 		
		Test the endianness of the processor by "storing" 1 as a multi-byte
		number and "retrieving" its first byte.  Since the compiler knows
		everything about such an object and about its use, the object and the
		test on it will collapse completely at compile-time. 
	*/
	union system_endianness_detection
	{
		uint16_t test_value;
		char test_array[sizeof(uint16_t)];

		system_endianness_detection() : test_value(1) { }

		//The most significant byte is on the left end of a word.
		bool is_big_endian() const { return test_array[0] == 0; }

		//The most significant byte is on the right end of a word.
		bool is_little_endian() const { return test_array[0] != 0; }
	};


	/* 
	    Store an object of type 'T' in memory in the byte order indicated by
		'wantBig'.
		
				if 'wantBig' = true
					big-endian
				else little-endian. 
		
		- Provide access to the object via a conversion constructor and a
		  conversion operator, swapping bytes on input and output if the
		  processor's byte order differs from the desired byte order. 
		
		- Use the class to define values for example:
			conditional_endian<int, true> value; //definition

		- When the value is "ASSIGNED" take the value as stored in the medium. 
			value = 5;

		- When the value is "ACCESSED" the operation () it is called fix the endian order.
			int value_copy = value; 
	
	*/
	template <typename T, bool force_big_endian>
	class conditional_endianness
	{
	public:
		conditional_endianness() { }

		conditional_endianness(const T& val) : m_stored_value(permute_endian(val)) { }

		/*
		    Called when the instance is accessed. For example:
			
			conditional_endian<int, true> value; //definition
			int value_copy = value;  //the operation () it is called.
		*/
		operator T() const { return permute_endian(m_stored_value); }

	private:
		/* 
			Swap bytes if the processor byte order differs from 
			the specified memory order. 
		*/
		static T permute_endian(const T& val)
		{
			// If the processor byte order is the same as the desired byte
			// order, simply return the argument unchanged. 
			if (system_endianness_detection().is_big_endian() == force_big_endian)
				return val;				
			else
			{ 
				// The processor byte order differs from the specified memory
				// order, so swap the bytes of the argument before returning it.
				T ret;

				char* dst = reinterpret_cast<char*>(&ret);
				const char* src = reinterpret_cast<const char*>(&val + 1);

				for (size_t i = 0; i < sizeof(T); i++)
					*dst++ = *--src;

				return ret;
			}
		}
		
		//This is the actual value read from media in same endian as stored.
		T m_stored_value;					
	};
	
	/*
		Maintain an object in big-endian order, regardless of the host
		machine's native byte order. 
	*/
	typedef conditional_endianness<uint64_t, true> uint64_t_big;
	typedef conditional_endianness<uint32_t, true> uint32_t_big;
	typedef conditional_endianness<uint16_t, true> uint16_t_big;

	/*
		Maintain an object in little-endian order, regardless of the host
		machine's native byte order. 
	*/
	typedef conditional_endianness<uint64_t, false> uint64_t_lit;
	typedef conditional_endianness<uint32_t, false> uint32_t_lit;
	typedef conditional_endianness<uint16_t, false> uint16_t_lit;


	//  unaligned little endian specialization
	template <typename T, bool force_big_endian, uint16_t n_bits>
	class unaligned_conditional_endianness
	{
	public:
		unaligned_conditional_endianness(){}
		
		unaligned_conditional_endianness(const T& val){save_endian(val);}

		 unaligned_conditional_endianness & operator=(const T& val) { save_endian(val); return *this; }

		operator T() const {return load_endian();}
	private:
		/* 
			Swap bytes if the processor byte order differs from 
			the specified memory order. 
		*/
		T load_endian() const
		{
			// If the processor byte order is the same as the desired byte
			// order, simply return the argument unchanged. 
			if (system_endianness_detection().is_big_endian() == force_big_endian)
			{	
				T* raw = static_cast<T*>((void*)(&m_stored_value[0]));
				return *raw;
			}
			else
			{ 
				// The processor byte order differs from the specified memory
				// order, so swap the bytes of the argument before returning it.
				T ret;

				uint8_t* dst = reinterpret_cast<uint8_t*>(&ret);
				const uint8_t* src = reinterpret_cast<const uint8_t*>(&m_stored_value[(n_bits/8)]);

				for (size_t i = 0; i < sizeof(T); i++)
					*dst++ = *--src;

				return ret;
			}
		}

		void save_endian(const T val)
		{
			const uint8_t* src = reinterpret_cast<const uint8_t*>(&val);				
			if (system_endianness_detection().is_big_endian() == force_big_endian)
			{
				for (size_t i = 0; i < sizeof(T); i++)
					m_stored_value[i] = *src++;
			}
			else
			{ 
				for (size_t i = 0; i < sizeof(T); i++)
					m_stored_value[(sizeof(T)-1)-i] = *src++;
			}
		}

		//This is the actual value read from media in same endian as stored.
		uint8_t m_stored_value[n_bits/8];
	};

	typedef unaligned_conditional_endianness<uint64_t, true, 64> uint64_bigendia_t;
	typedef unaligned_conditional_endianness<uint32_t, true, 32> uint32_bigendia_t;
	typedef unaligned_conditional_endianness<int32_t, true, 32> int32_bigendia_t;
	typedef unaligned_conditional_endianness<uint16_t, true, 16> uint16_bigendia_t;
	typedef unaligned_conditional_endianness<int16_t, true, 16>  int16_bigendia_t;

	typedef unaligned_conditional_endianness<uint64_t, false, 64> uint64_litendia_t;
	typedef unaligned_conditional_endianness<uint32_t, false, 32> uint32_litendia_t;
	typedef unaligned_conditional_endianness<uint16_t, false, 16> uint16_litendia_t;
}	