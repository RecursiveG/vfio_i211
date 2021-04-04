#include "pcap_dumper.h"

PcapDumper::PcapDumper(const std::string &fifo) {
    pcap_ = pcap_open_dead(DLT_EN10MB, 65536);
    dumper_ = pcap_dump_open(pcap_, fifo.c_str());
};

PcapDumper::~PcapDumper() {
    pcap_dump_close(dumper_);
    pcap_close(pcap_);
}

void PcapDumper::Dump(const std::string &data) {
    pcap_pkthdr hdr = {};
    hdr.caplen = data.size();
    hdr.len = data.size();
    pcap_dump(reinterpret_cast<u_char *>(dumper_), &hdr,
              reinterpret_cast<const u_char *>(data.data()));
    pcap_dump_flush(dumper_);
}
