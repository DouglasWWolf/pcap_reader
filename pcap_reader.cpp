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
    uint16_t    fcs;
    uint16_t    link_type;
} header;
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
    pcap_header_t header;

    // Open the input file
    fp_ = fopen(filename.c_str(), "r");
    
    // Complain if we can't open the input file
    if (fp_ == nullptr) throwRuntime("Can't open %s", filename.c_str());

    // Read in the PCAP header
    if (fread(&header, 1, sizeof(header), fp_) != sizeof(header))
        throwRuntime("File is not a nanosecond/little-endian PCAP file");

    // If the magic number is wrong, complain about it
    if (header.magic_number != 0xA1B23C4D)
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


