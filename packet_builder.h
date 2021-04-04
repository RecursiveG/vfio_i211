#include "result.h"
#include "udp_checksum.h"
#include "vfio.h"
#include <arpa/inet.h>
#include <array>
#include <cinttypes>
#include <netinet/ether.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <string>
#include <sys/types.h>

constexpr uint64_t kSrcEther = 0xEA22CB41EF77;
constexpr uint64_t kDefaultDstEther = 0xE24BD54A54A2;
const char *const kSrcIp = "fd00::1";

struct udp_packet_header {
    ethhdr eth;  // 14
    ip6_hdr ip6; // 40
    udphdr udp;  // 8
} __attribute__((packed));
static_assert(sizeof(udp_packet_header) == 62);

struct icmp6_packet {
    ethhdr eth;
    ip6_hdr ip6;
    nd_neighbor_advert icmp6;
    uint8_t opt_type;
    uint8_t opt_size;
    char target_ether[6];
} __attribute__((packed));

inline void set_ethaddr_array(uint64_t ethaddr, uint8_t *arr) {
    int i = 6;
    while (i-- > 0) {
        arr[i] = ethaddr & 0xffu;
        ethaddr >>= 8;
    }
};

class NetworkPacket {
  public:
    NetworkPacket(void *va, uint64_t iova, uint64_t length)
        : va_(va), iova_(iova), length_(length) {}

    Result<ResultVoid, std::string> BuildNeighAdvert(const char peermac[6],
                                                     const in6_addr &peerip) {
        icmp6_packet *pkt = static_cast<icmp6_packet *>(va_);
        memset(pkt, 0, sizeof(icmp6_packet));
        set_ethaddr_array(kSrcEther, pkt->eth.h_source);
        memcpy(pkt->eth.h_dest, peermac, 6);
        pkt->eth.h_proto = htobe16(ETH_P_IPV6);

        pkt->ip6.ip6_flow = 0;
        pkt->ip6.ip6_vfc = 0x60;
        pkt->ip6.ip6_plen = htobe16(sizeof(nd_neighbor_advert) + 8);
        pkt->ip6.ip6_nxt = IPPROTO_ICMPV6;
        pkt->ip6.ip6_hlim = 255;
        int success = inet_pton(AF_INET6, kSrcIp, &pkt->ip6.ip6_src);
        if (!success)
            return Err("cannot set ipv6 address");
        memcpy(&pkt->ip6.ip6_dst, &peerip, sizeof(in6_addr));

        pkt->icmp6.nd_na_hdr.icmp6_type = ND_NEIGHBOR_ADVERT;
        pkt->icmp6.nd_na_hdr.icmp6_data32[0] = ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE;
        memcpy(&pkt->icmp6.nd_na_target, &pkt->ip6.ip6_src, sizeof(in6_addr));
        pkt->opt_type = 2;
        pkt->opt_size = 1;
        set_ethaddr_array(kSrcEther, reinterpret_cast<uint8_t *>(pkt->target_ether));

        UdpChecksumer checker;
        checker.update(pkt->ip6.ip6_src);
        checker.update(pkt->ip6.ip6_dst);
        checker.update_be(pkt->ip6.ip6_plen);
        checker.update_le(IPPROTO_ICMPV6);
        checker.update(reinterpret_cast<char *>(&pkt->icmp6),
                       (sizeof(nd_neighbor_advert) + 8) / 2);
        pkt->icmp6.nd_na_hdr.icmp6_cksum = htobe16(checker.get());

        packet_size_ = sizeof(icmp6_packet);
        return {};
    }

    Result<ResultVoid, std::string> BuildUdp(const std::string &payload) {
        if (sizeof(udp_packet_header) + payload.size() > length_)
            return Err("payload too large");

        udp_packet_header *packet_hdr = static_cast<udp_packet_header *>(va_);

        // prepare data
        set_ethaddr_array(kDefaultDstEther, packet_hdr->eth.h_dest);
        set_ethaddr_array(kSrcEther, packet_hdr->eth.h_source);
        packet_hdr->eth.h_proto = htobe16(ETH_P_IPV6);

        packet_hdr->ip6.ip6_flow = 0;
        packet_hdr->ip6.ip6_vfc = 0x60;
        packet_hdr->ip6.ip6_plen = htobe16(/*udp*/ 8 + payload.size());
        packet_hdr->ip6.ip6_nxt = IPPROTO_UDP;
        packet_hdr->ip6.ip6_hlim = 32;

        int success = 0;
        success += inet_pton(AF_INET6, kSrcIp, &packet_hdr->ip6.ip6_src);
        success += inet_pton(AF_INET6, "fd00::2", &packet_hdr->ip6.ip6_dst);
        if (success != 2) {
            return Err("cannot set ipv6 address");
        }

        packet_hdr->udp.uh_sport = htobe16(6200);
        packet_hdr->udp.uh_dport = htobe16(6300);
        packet_hdr->udp.uh_ulen = htobe16(8 + payload.size());

        char *pkt_payload = static_cast<char *>(va_) + sizeof(udp_packet_header);

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

        packet_size_ = sizeof(udp_packet_header) + payload.size();
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
