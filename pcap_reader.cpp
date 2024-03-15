//=============================================================================
// pcap_reader.cpp - This class reads PCAP file, and expects them to use
//                   nanosecond timestamp resolution and for the header 
//                   fields to be little-endian.
//=============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdarg>
#include <stdexcept>
#include "pcap_reader.h"

using namespace std;

//=============================================================================
// Fields broken out from an Ethernet/IPv4/UDP/RDMX packet
//=============================================================================
#pragma pack(push, 1)
struct network_order_header_t
{
    uint8_t     eth_dst_mac[6];
    uint8_t     eth_src_mac[6];
    uint16_t    eth_type;
    
    uint8_t     ip4_version;
    uint8_t     ip4_dsf;
    uint16_t    ip4_length;
    uint16_t    ip4_id;
    uint16_t    ip4_flags;
    uint8_t     ip4_ttl;
    uint8_t     ip4_protocol;
    uint16_t    ip4_checksum;
    uint32_t    ip4_src_ip;
    uint32_t    ip4_dst_ip;

    uint16_t    udp_src_port;
    uint16_t    udp_dst_port;
    uint16_t    udp_length;
    uint16_t    udp_checksum;

    uint16_t    rdmx_magic;
    uint64_t    rdmx_target;
};
#pragma pack(pop)
//=============================================================================



//=============================================================================
// throwRuntime() - Throws a runtime exception
//=============================================================================
static void throwRuntime(const char* fmt, ...)
{
    char buffer[1024];
    va_list ap;
    va_start(ap, fmt);
    vsprintf(buffer, fmt, ap);
    va_end(ap);

    throw runtime_error(buffer);
}
//=============================================================================



//=============================================================================
// open() - Opens a PCAP file.   
//=============================================================================
void CPcapReader::open(string filename)
{

    // Open the input file
    fp_ = fopen(filename.c_str(), "r");
    
    // Complain if we can't open the input file
    if (fp_ == nullptr) throwRuntime("Can't open %s", filename.c_str());

    // Read in the PCAP header
    if (fread(&header_, 1, sizeof(header_), fp_) != sizeof(header_))
        throwRuntime("File is not a nanosecond/little-endian PCAP file");

    // If the magic number is wrong, complain about it.   That second "magic
    // number" check is there to allow us to treat microsecond timestamps 
    // as though they were nanosecond timestamps
    if (header_.magic_number != 0xA1B23C4D && header_.magic_number != 0xA1B2C3D4)
        throwRuntime("File is not a nanosecond/little-endian PCAP file");
}
//=============================================================================


//=============================================================================
// close() - Closes the file if it's open
//=============================================================================
void CPcapReader::close()
{
    if (fp_)
    {
        fclose(fp_);
        fp_ = nullptr;
    }
}
//=============================================================================


//=============================================================================
// get_next_packet() - Fetches the next packet from the file.
//
// Returns 'true' on success, or 'false' if no more packets are available
//=============================================================================
bool CPcapReader::get_next_packet(pcap_packet_t* packet)
{
    // If there is no file open, treat it as an EOF
    if (fp_ == nullptr)
        throwRuntime("File not open");

    // If we don't have a full packet header available, we're at EOF
    if (fread(packet, 1, 16, fp_) != 16)
        return false;

    // If the packet data won't fit into the data field, something is awry.
    if (packet->length > sizeof(packet->data))
        throwRuntime("Bad packet length [%u] !\n", packet->length);

    // If we can't read all of the packet data, we're at EOF
    if (fread(packet->data, 1, packet->length, fp_) != packet->length) 
        return false;

    // Otherwise, tell the caller they have a packet available
    return true;        
}
//=============================================================================


//=============================================================================
// swap16() - Swaps the endian-ness of a 16-bit field
//=============================================================================
static uint16_t swap16(uint16_t value)
{
    unsigned char* byte = (unsigned char*)&value;
    return (byte[0] << 8) | byte[1];
}
//=============================================================================


//=============================================================================
// swap32() - Swaps the endian-ness of a 32-bit field
//=============================================================================
static uint32_t swap32(uint32_t value)
{
    unsigned char* byte = (unsigned char*)&value;
    return (byte[0] << 24) |
           (byte[1] << 16) |
           (byte[2] <<  8) |
           (byte[3]      );
}
//=============================================================================


//=============================================================================
// swap64() - Swaps the endian-ness of a 64-bit field
//=============================================================================
static uint64_t swap64(uint64_t value)
{
    unsigned char* byte = (unsigned char*)&value;
    return ((uint64_t)byte[0] << 56) |
           ((uint64_t)byte[1] << 48) |
           ((uint64_t)byte[2] << 40) |
           ((uint64_t)byte[3] << 32) |
           ((uint64_t)byte[4] << 24) |
           ((uint64_t)byte[5] << 16) |
           ((uint64_t)byte[6] <<  8) |
           ((uint64_t)byte[7]      );
}
//=============================================================================


#if 0
//=============================================================================
// print_header() - A convenient utility function for debugging during
//                  development of this class.
//=============================================================================
static void print_header(eth_header_t& header)
{
    const char* tf[] = {"false", "true"};
    int i;
    printf("eth dst mac : ");
    for (i=0; i<6; ++i) 
    {
        if (i) printf("-");
        printf("%02X", header.eth_dst_mac[i]);
    }
    printf("\n");

    printf("eth src mac : ");
    for (i=0; i<6; ++i) 
    {
        if (i) printf("-");
        printf("%02X", header.eth_src_mac[i]);
    }
    printf("\n");

    printf("eth_type    : 0x%04X\n",    header.eth_type);
    
    printf("ip4_version : 0x%02X\n",    header.ip4_version);
    printf("ip4_dsf     : 0x%02X\n",    header.ip4_dsf);
    printf("ip4_length  : %d\n",        header.ip4_length);
    printf("ip4_id      : 0x%04X\n",    header.ip4_id);
    printf("ip4_flags   : 0x%04X\n",    header.ip4_flags);    
    printf("ip4_ttl     : %d\n",        header.ip4_ttl);
    printf("ip4_proto   : %d\n",        header.ip4_protocol);
    printf("ip4_checksum: 0x%04X\n",    header.ip4_checksum);        
    printf("ip4_src_ip  : 0x%08X\n",    header.ip4_src_ip);
    printf("ip4_dst_ip  : 0x%08X\n",    header.ip4_dst_ip);
    
    printf("udp_src_port: %d\n",        header.udp_src_port);    
    printf("udp_dst_port: %d\n",        header.udp_dst_port);  
    printf("udp_length  : %d\n",        header.udp_length); 
    printf("udp_checksum: 0x%04X\n",    header.udp_checksum);             
    
    printf("rdmx_magic  : 0x%02X\n",    header.rdmx_magic);
    printf("rdmx_target : 0x%016lX\n",  header.rdmx_target);
    
    printf("is_ethernet : %s\n", tf[header.is_ethernet]);
    printf("is_ipv4     : %s\n", tf[header.is_ipv4    ]);
    printf("is_udp      : %s\n", tf[header.is_udp     ]);
    printf("is_rdmx     : %s\n", tf[header.is_rdmx    ]);            
}
//=============================================================================
#endif

//=============================================================================
// parse_packet_headers() - Parses the headers of an Ethernet/IPv4/UDP/RDMX
//                          packet into a structure with all of the fields
//                          broken out.
//=============================================================================
void CPcapReader::parse_packet_headers(unsigned char* data, eth_header_t* header)
{
    // Get a convenient reference to the "network order"
    // Ethernet/IPv4/UDP/RDMX header
    network_order_header_t& no_packet = *(network_order_header_t*)data;

    // Get a convenient reference to the caller's result structure
    eth_header_t& result = *(eth_header_t*)header;

    // Copy the MAC addresses into our result structure
    memcpy(result.eth_dst_mac, no_packet.eth_dst_mac, 6);
    memcpy(result.eth_src_mac, no_packet.eth_src_mac, 6);

    // Copy the remaining Ethernet header field
    result.eth_type     = swap16(no_packet.eth_type);
    
    // Copy the IPv4 header fields
    result.ip4_version  = no_packet.ip4_version;
    result.ip4_dsf      = no_packet.ip4_dsf;
    result.ip4_length   = swap16(no_packet.ip4_length);
    result.ip4_id       = swap16(no_packet.ip4_id);
    result.ip4_flags    = swap16(no_packet.ip4_flags);
    result.ip4_ttl      = no_packet.ip4_ttl;
    result.ip4_protocol = no_packet.ip4_protocol;
    result.ip4_checksum = swap16(no_packet.ip4_checksum);
    result.ip4_src_ip   = swap32(no_packet.ip4_src_ip);
    result.ip4_dst_ip   = swap32(no_packet.ip4_dst_ip);

    // Copy the UDP header fields
    result.udp_src_port = swap16(no_packet.udp_src_port);
    result.udp_dst_port = swap16(no_packet.udp_dst_port);
    result.udp_length   = swap16(no_packet.udp_length);
    result.udp_checksum = swap16(no_packet.udp_checksum);

    // Copy the RDMX header fields
    result.rdmx_magic   = swap16(no_packet.rdmx_magic);
    result.rdmx_target  = swap64(no_packet.rdmx_target);

    // Is this an Ethernet packet that we understand?
    result.is_ethernet = (result.eth_type == 0x800);

    // Is this an IPv4 packet that we understand?
    result.is_ipv4 = result.is_ethernet && (result.ip4_version == 0x45);

    // Is this a UDP packet that we understand?
    result.is_udp = result.is_ipv4 && (result.ip4_protocol == 0x11);

    // Is this an RDMX packet that we understand?
    result.is_rdmx = result.is_udp && (result.rdmx_magic == 0x0122);
}    
//=============================================================================
