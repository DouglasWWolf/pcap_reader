//=============================================================================
// This is a simple demo of the CPcapReader class
//=============================================================================
#include <unistd.h>
#include <stdio.h>
#include <stdexcept>
#include "pcap_reader.h"

CPcapReader   reader;

void execute();

int main()
{
    try
    {
        execute();
    }
    catch(const std::runtime_error& e)
    {
        printf("%s\n", e.what());
    }

}


void execute()
{
    pcap_packet_t packet;
    eth_header_t header;

    reader.open("chargen-udp.pcap");

    while (reader.get_next_packet(&packet))
    {
        printf("Timestamp        : %u seconds, %u ns\n", packet.ts_seconds, packet.ts_nanoseconds);
        printf("Data Length      : %u bytes\n", packet.length);
        printf("First three bytes: 0x%02X  0x%02X  0x%02X\n", packet.data[0], packet.data[1], packet.data[2]);
        
        reader.parse_packet_headers(packet.data, &header);
        printf("\n");
    }
}