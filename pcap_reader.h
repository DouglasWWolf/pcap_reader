//=============================================================================
// pcap_reader.h - This class reads PCAP files, and expects them to use
//                 nanosecond timestamp resolution and for the header fields
//                 to be little-endian.
//=============================================================================
#include <string>
#include <cstdint>


//=============================================================================
// Fields broken out from an Ethernet/IPv4/UDP/RDMX packet
//=============================================================================
struct eth_header_t
{
    //----------------------------------------------------------------------
    // These "is_xxx" fields are cumulative - if one of them is 'true', it 
    // implies that all of the "is_xxx" fields above it are also true.
    //
    // For example, if "is_rdmx" is true, then "is_udp", "is_ipv4" and 
    // "is_ethernet" are all also gauranteed to be true.
    //----------------------------------------------------------------------

    // Is this packet probably an Ethernet packet?
    bool        is_ethernet;
    
    // Is this packet probably a simple IPv4 packet?
    bool        is_ipv4;
    
    // Is this packet probably a UDP packet?
    bool        is_udp;
    
    // Is this packet probably an RDMX packet?
    bool        is_rdmx;

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
//=============================================================================


//=============================================================================
// This is the header of a PCAP file
//=============================================================================
#pragma pack(push, 1)
struct pcap_header_t
{
    uint32_t    magic_number;
    uint16_t    major_version;
    uint16_t    minor_version;
    uint32_t    reserved1;
    uint32_t    reserved2;
    uint32_t    snaplen;
    uint32_t    link_type;
};
#pragma pack(pop)
//=============================================================================


//=============================================================================
// This is a PCAP packet, returned by get_next_packet().  Field "length"
// describes the length of the data in "data"
//=============================================================================
#pragma pack(push, 1)
struct pcap_packet_t
{
    uint32_t    ts_seconds;
    uint32_t    ts_nanoseconds;
    uint32_t    length;
    uint32_t    reserved;
    uint8_t     data[10000];
};
#pragma pack(pop)
//=============================================================================


//=============================================================================
// This class is used to sequentially read a PCAP file
//=============================================================================
class CPcapReader
{
public:

    // Constructor / destructor
    CPcapReader() {fp_ = nullptr;}
    ~CPcapReader() {close();}

    // Call this to open a PCAP file.
    // Will throw std::runtime_error on failure.
    void    open(std::string filename);

    // This fetches the next packet from an open file.  Returns false when there
    // are no more packets available to read.  
    // Will throw std::runtime_error on failure.    
    bool    get_next_packet(pcap_packet_t*);

    // Call this to close the input file
    void    close();

    // This parses the headers of a raw packet into fields
    void    parse_packet_headers(unsigned char* data, eth_header_t* header);

protected:

    FILE*   fp_;

    // This is the PCAP file header that was read in
    pcap_header_t header_;

};
//=============================================================================



