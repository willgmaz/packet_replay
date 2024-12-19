#include "traffic_replay.hpp"
#include <cmd_actions/offline_pcaps_action_stats_t.hpp>
#include <cmd_actions/offline_pcaps_action_replay_folder_t.hpp>
#include <cmd_actions/pcap_devs_action_getif_t.hpp>
#include <cmd_actions/pcap_devs_action_getif_by_number_t.hpp>

using namespace replay;

#define VERSION "1.2.4.0"
void print_version() { std::cout << "pcap replay tool: " << VERSION << std::endl; }

void help()
{
	print_version();
	std::cout << "Usage:" << std::endl;
	std::cout << "    -l" << std::endl;
	std::cout << "         list interfaces" << std::endl;
	std::cout << std::endl;
	std::cout << "    -p pcap_path" << std::endl;
	std::cout << "         print stats about pcap file" << std::endl;
	std::cout << std::endl;
	std::cout << "    -s folder_pcap_path" << std::endl;
	std::cout << "         print stats about all pcap files" << std::endl;
	std::cout << std::endl;
	std::cout << "    -p pcap_path -i interface_name" << std::endl;
	std::cout << "         replay a pcap to the selected interface" << std::endl;
	std::cout << std::endl;
	std::cout << "    -p pcap_path -s source_interface_name -d destination_interface_name" << std::endl;
	std::cout << "         replay a pcap from source to destination selected interface" << std::endl;
	std::cout << std::endl;
	std::cout << "    -p pcap_path -sip source_ip -dip destination_ip" << std::endl;
	std::cout << "         replay a pcap from source IP to destination IP. Map from IP to interface will be done automatically" << std::endl;
	std::cout << std::endl;
	std::cout << "    -r pcap_folder_path|pcap_file_path -sip source_ip -dip destination_ip" << std::endl;
	std::cout << "         replay a pcaps in folder from source IP to destination IP. Map from IP to interface will be done automatically" << std::endl;
	std::cout << std::endl;
	std::cout << "    -r pcap_folder_path|pcap_file_path -si source_interface_name -di destination_interface_name -sip source_ip -dip destination_ip" << std::endl;
	std::cout << "         replay a pcaps in folder from any source IP to any destination IP." << std::endl;
	std::cout << std::endl;
	std::cout << "    -r pcap_folder_path|pcap_file_path -s source_interface_name -d destination_interface_name" << std::endl;
	std::cout << "         replay a pcaps in folder pcap_folder_path from source to destination selected interface" << std::endl;
	std::cout << std::endl;
	std::cout << "    -v" << std::endl;
	std::cout << "        print command line version." << std::endl;

	std::cout << std::endl;
	std::cout << std::endl;
	std::cout << "Fake TrafficIQ command lines." << std::endl;
	std::cout << " Regression testing: -ia 2 -ea 3 -tfile pcap_file.pcap -iport * -eport 0 -retry 5 -path E:/HPD" << std::endl;
}

void pcap_stats(const char* pcap_file)
{
	offline_pcap_t pcap;
	if (!pcap.open(pcap, pcap_file)) {
		std::cout << "Pcap is corrupted or format not supported" << std::endl;
		return;
	}

	pcap_stat_t sta = pcap.dump_stats();
	std::cout << "Pcap stats:" << std::endl;
	std::cout << "   start_time:   " << sta.start_time.tv_sec << std::endl;
	std::cout << "   end_time:     " << sta.end_time.tv_sec << std::endl;
	std::cout << "   packet count: " << sta.count << std::endl;
}

void replay_pcap_if(const char* pcap_file, const char* src_if, const char* dst_if, bool stats = true)
{
	if (stats)
		std::cout << "Replaying:    " << std::endl;

	offline_pcap_t pcap_replay;
	if (!pcap_replay.open(pcap_replay, pcap_file)) {
		std::cout << "Error, Traffic file:" << pcap_file << std::endl << "   Note: Path to file is wrong or Pcap is corrupted or Pcap format not supported" << std::endl;
		return;
	}

	pcap_layer2_split_replay_t split;
	if (split.init(src_if, dst_if))
		pcap_layer2_split_replay_t::play_back(split, pcap_replay);
	else
	{
		std::cout << "Error, Traffic file:" << pcap_file << "Note: Failed configuring interfaces." << std::endl;
		return;
	}

	if (stats)
	{
		if (split.has_bad_ptks())
		{
			std::cout << "Falied stats: " << std::endl;
			std::cout << "  L2 non-suported packets: " << split.get_l2_non_supported_packet_count() << std::endl;
			std::cout << "  Failed packet count:     " << split.get_failed_packet_count() << std::endl;
		}
	}
	else
	{
		if (split.has_bad_ptks())
			std::cout << "Warnning, Traffic file:" << pcap_file << "Note: Some packets failed, usualy are jumbo packtes." << std::endl;
	}

	if (stats)
	{
		std::cout << "Replay completed. " << std::endl
			<< "   packet count:  " << split.get_replayed_packet_count() << std::endl;
	}
	else
		std::cout << "OK. packet count : " << split.get_replayed_packet_count() << std::endl;
}

void replay_pcap_ip(const char* pcap_file, const char* src_ip, const char* dst_ip)
{
	pcap_devs_t devs_1;	
	pcap_devs_action_getif_t src_if(src_ip);
	devs_1.get_ifs(src_if);

	pcap_devs_t devs_2;
	pcap_devs_action_getif_t dst_if(dst_ip);
	devs_2.get_ifs(dst_if);

	replay_pcap_if(pcap_file, src_if.m_id.c_str(), dst_if.m_id.c_str(), true);
}

void traffic_iq_replay(const char* src_if_n, const char* dst_if_n, 
	const char* pcap_file_name, const char* pcap_folder)
{
	pcap_devs_t devs_1;
	pcap_devs_action_getif_by_number_t src_if(atoi(src_if_n));
	devs_1.get_ifs(src_if);

	pcap_devs_t devs_2;
	pcap_devs_action_getif_by_number_t dst_if(atoi(dst_if_n));
	devs_2.get_ifs(dst_if);

	std::string path(pcap_folder);
	path.append("/");
	path.append(pcap_file_name);

	replay_pcap_if(path.c_str(), src_if.m_id.c_str(), dst_if.m_id.c_str(), false);
}

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		help();
		return 0;
	}

	if (argc == 2) {
		if (std::string(argv[1]) == "-l")
		{
			pcap_devs_t devs;
			pcap_devs_action_dump_t dump(std::cout);

			devs.get_ifs(dump);
			return 0;
		}

		if (std::string(argv[1]) == "-v")
		{
			print_version();
			return 0;
		}
	}

	if (argc == 3) {
		if (std::string(argv[1]) == "-p")
		{
			offline_pcap_t pcap;
			pcap.open(pcap, argv[2]);

			pcap_stat_t sta = pcap.dump_stats();
			std::cout << "Pcap stats:" << std::endl;
			std::cout << "   start_time: " << sta.start_time.tv_sec << std::endl;
			std::cout << "   end_time:   " << sta.end_time.tv_sec << std::endl;
			std::cout << "   pkts:       " << sta.count << std::endl;
			return 0;
		}
		else if (std::string(argv[1]) == "-s")
		{
			offline_pcaps_action_stats_t stats;
			windows::fs::dir_files(argv[2], stats);
			stats.dump_stats();
			return 0;
		}
	}

	if (argc == 5) {
		if (std::string(argv[1]) == "-p" &&
			std::string(argv[3]) == "-i")
		{
			offline_pcap_t pcap;
			pcap.open(pcap, argv[2]);

			pcap_mirror_replay_t capture;
			capture.init(argv[4]);
			pcap_mirror_replay_t::play_back(capture, pcap);
			return 0;
		}
	}

	if (argc == 7)
	{
		if (std::string(argv[1]) == "-p" &&
			std::string(argv[3]) == "-s" &&
			std::string(argv[5]) == "-d")
		{
			pcap_stats(argv[2]);
			replay_pcap_if(argv[2], argv[4], argv[6]);
			return 0;
		}
		else if (std::string(argv[1]) == "-r" &&
				 std::string(argv[3]) == "-s" &&
				 std::string(argv[5]) == "-d")
		{
			offline_pcaps_action_replay_t stats;
			if (!stats.init(argv[4], argv[6], false))
			{
				std::cout << "Failed configuring interfaces." << std::endl;
				return 0;
			}

			std::cout << "Replaying folder: " << argv[2] << std::endl;
			windows::fs::dir_files(argv[2], stats);
			stats.dump_stats(std::cout);
			return 0;
		}
		else if (std::string(argv[1]) == "-r" &&
			std::string(argv[3]) == "-sip" &&
			std::string(argv[5]) == "-dip")
		{
			offline_pcaps_action_replay_t stats;
			if (!stats.init(argv[4], argv[6], true))
			{
				std::cout << "Failed configuring interfaces." << std::endl;
				return 0;
			}

			std::cout << "Replaying folder: " << argv[2] << std::endl;
			windows::fs::dir_files(argv[2], stats);
			stats.dump_stats(std::cout);
			return 0;
		}
		else if (std::string(argv[1]) == "-p" &&
			std::string(argv[3]) == "-sip" &&
			std::string(argv[5]) == "-dip")
		{
			pcap_stats(argv[2]);
			replay_pcap_ip(argv[2], argv[4], argv[6]);
			return 0;
		}
	}

	if (argc == 11) {
		if (std::string(argv[1]) == "-r" &&
			std::string(argv[3]) == "-si" &&
			std::string(argv[5]) == "-di" &&
			std::string(argv[7]) == "-sip" &&
			std::string(argv[9]) == "-dip")
		{
			try
			{
				offline_pcaps_action_replay_t stats;
				if (!stats.init(argv[4], argv[6], argv[8], argv[10])) {
					std::cout << "Failed configuring interfaces or IP formats are incorrect." << std::endl;
					return 0;
				}

				std::cout << "Replaying folder: " << argv[2] << std::endl;
				windows::fs::dir_files(argv[2], stats);
				stats.dump_stats(std::cout);
				return 0;
			}
			catch (const std::exception& ex)
			{
				std::cout << "error replaying. error: " << ex.what() << std::endl;
			}
			catch (...)
			{
				std::cout << "error replaying. " << std::endl;
			}
		}
	}

	//TrafficIQ fake options.
	if (argc == 15) {
		//-ia 2 -ea 3 -tfile pcap_file.pcap -iport * -eport 0 -retry 5 -path E:/HPD
		if (std::string(argv[1]) == "-ia" &&
			std::string(argv[3]) == "-ea" &&
			std::string(argv[5]) == "-tfile" &&
			std::string(argv[7]) == "-iport" &&
			std::string(argv[9]) == "-eport" &&
			std::string(argv[11]) == "-retry" &&
			std::string(argv[13]) == "-path")
		{
			traffic_iq_replay(argv[2], argv[4], argv[6], argv[14]);
			return 0;
		}
	}

	help();
	return 0; 
}
