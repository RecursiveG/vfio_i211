#include "result.h"
#include "udp_checksum.h"
#include "vfio.h"
#include <arpa/inet.h>
#include <array>
#include <cinttypes>
#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <string>
#include <sys/types.h>

struct packet_header {
    ethhdr eth;  // 14
    ip6_hdr ip6; // 40
    udphdr udp;  // 8
} __attribute__((packed));
static_assert(sizeof(packet_header) == 62);

class NetworkPacket {
  public:
    NetworkPacket(void *va, uint64_t iova, uint64_t length)
        : va_(va), iova_(iova), length_(length) {}

    Result<ResultVoid, std::string> SetContent(const std::string &payload) {
        if (sizeof(packet_header) + payload.size() > length_)
            return Err("payload too large");

        auto set_ethaddr_array = [](uint64_t ethaddr, uint8_t *arr) {
            int i = 6;
            while (i-- > 0) {
                arr[i] = ethaddr & 0xffu;
                ethaddr >>= 8;
            }
        };

        packet_header *packet_hdr = static_cast<packet_header *>(va_);

        // prepare data
        set_ethaddr_array(0xE24BD54A54A2, packet_hdr->eth.h_dest);
        set_ethaddr_array(0xEA22CB41EF77, packet_hdr->eth.h_source);
        packet_hdr->eth.h_proto = htobe16(ETH_P_IPV6);

        packet_hdr->ip6.ip6_flow = 0;
        packet_hdr->ip6.ip6_vfc = 0x60;
        packet_hdr->ip6.ip6_plen = htobe16(/*udp*/ 8 + payload.size());
        packet_hdr->ip6.ip6_nxt = IPPROTO_UDP;
        packet_hdr->ip6.ip6_hlim = 32;

        int success = 0;
        success += inet_pton(AF_INET6, "fd00::1", &packet_hdr->ip6.ip6_src);
        success += inet_pton(AF_INET6, "fd00::2", &packet_hdr->ip6.ip6_dst);
        if (success != 2) {
            return Err("cannot set ipv6 address");
        }

        packet_hdr->udp.uh_sport = htobe16(6200);
        packet_hdr->udp.uh_dport = htobe16(6300);
        packet_hdr->udp.uh_ulen = htobe16(8 + payload.size());

        char *pkt_payload = static_cast<char *>(va_) + sizeof(packet_header);

        memcpy(pkt_payload, payload.c_str(), payload.size());

        UdpChecksumer checker;
        checker.update(packet_hdr->ip6.ip6_src);
        checker.update(packet_hdr->ip6.ip6_dst);
        checker.update_le(8 + payload.size());
        checker.update_le(IPPROTO_UDP);
        checker.update(packet_hdr->udp.uh_sport);
        checker.update(packet_hdr->udp.uh_dport);
        checker.update(packet_hdr->udp.uh_ulen);
        checker.update(payload.c_str(), (payload.size() + 1) / 2);
        packet_hdr->udp.uh_sum = htobe16(checker.get());

        packet_size_ = sizeof(packet_header) + payload.size();
        return {};
    }

    uint64_t iova() { return iova_; }
    uint64_t packet_size() { return packet_size_; }
    std::string dump() { return std::string{static_cast<char *>(va_), packet_size_}; }

  private:
    void *va_;
    uint64_t iova_;
    uint64_t length_;
    uint64_t packet_size_;
};
