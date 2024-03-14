//=============================================================================
// pcap_reader.h - This class reads PCAP files, and expects them to use
//                 nanosecond timestamp resolution and for the header fields
//                 to be little-endian.
//=============================================================================
#include <string>


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
    ~CPcapReader() {if (fp_) fclose(fp_);}

    // Call this to open a PCAP file.
    // Will throw std::runtime_error on failure.
    void    open(std::string filename);

    // This fetches the next packet from an open file.  Returns false when there
    // are no more packets available to read.  
    // Will throw std::runtime_error on failure.    
    bool    get_next_packet(pcap_packet_t*);

protected:

    FILE*   fp_;
 
};
//=============================================================================



