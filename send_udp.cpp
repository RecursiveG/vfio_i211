#include <iostream>

#include <arpa/inet.h>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <sys/mman.h>
#include <unistd.h>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "hw_defs.h"
#include "result.h"
#include "vfio.h"

using namespace std;
using std::string;

ABSL_FLAG(string, bdf, "", "BUS:DEVICE:FUNCTION of the NIC.");
ABSL_FLAG(string, group, "", "IOMMU group number");

class UdpChecksumer {
  public:
    template <bool be = true, typename T> void update(const T &t) {
        static_assert(sizeof(T) % 2 == 0);
        const uint16_t *ptr = reinterpret_cast<const uint16_t *>(&t);
        for (size_t i = 0; i < sizeof(T) / 2; i++) {
            if constexpr (be) {
                update_be(ptr[i]);
            } else {
                update_le(ptr[i]);
            }
        }
    }
    void update_le(uint16_t u) {
        val += u;
        val = (val & 0xFFFF) + (val >> 16);
    }
    void update_be(uint16_t u) { update_le(be16toh(u)); }

    void update(const char *data, int doubles) {
        const uint16_t *ptr = reinterpret_cast<const uint16_t *>(data);
        for (int i = 0; i < doubles; i++) {
            update_be(ptr[i]);
        }
    }
    uint16_t get() {
        uint16_t ret = (~val) & 0xFFFF;
        return ret == 0 ? 0xFFFF : ret;
    }

  private:
    uint32_t val = 0;
};

class IntelI211Device {
  public:
    IntelI211Device(VfioDevice *dev) : dev_(dev) {}

    // 8.7.12 Interrupt Mask Clear
    const uint64_t IMC = 0x150C;

    // 8.7.6 Extended Interrupt Mask Clear
    const uint64_t EIMC = 0x1528;

    // 8.2.1 Device Control Register
    const uint64_t CTRL = 0x0000;
    const uint64_t CTRL_SLU = 6;  // Set Link Up
    const uint32_t CTRL_RST = 26; // Port Software Reset

    // 8.2.2 Device Status Register
    const uint64_t STATUS = 0x0008;
    const uint32_t STATUS_PFRSTDONE = 21; // PF_RST_DONE
    const uint32_t STATUS_LU = 1;         // Link Up

    // 8.11.1 Transmit Control Register
    const uint64_t TCTL = 0x0400;
    const uint64_t TCTL_EN = 1; // Transmit enable

    // 8.11.10 8.11.11 Transmit Descriptor Base Address Low/High[0]
    const uint64_t TDBA64 = 0xE000;

    // 8.11.12 Transmit Descriptor Ring Length[0], number of bytes
    const uint64_t TDLEN = 0xE008;

    // 8.11.13 Transmit Descriptor Head[0]
    const uint64_t TDH = 0xE010;

    // 8.11.14 Transmit Descriptor Tail[0]
    const uint64_t TDT = 0xE018;

    // 8.11.15 Transmit Descriptor Control[0]
    const uint64_t TXDCTL = 0xE028;
    const uint32_t TXDCTL_ENABLE = 25; // Transmit Queue Enable

    // PCI Configuration space:COMMAND REG(0x4):bit #2
    void SetPcieBusMaster() {
        int val;
        auto bar7 = dev_->GetDeviceRegionInfo(VFIO_PCI_CONFIG_REGION_INDEX);
        pread(dev_->device(), &val, 2, bar7->offset + 4);
        val |= 4;
        pwrite(dev_->device(), &val, 2, bar7->offset + 4);
    }

    void MaskAllInterrupts() {
        // Being lazy and just write all 1 s
        dev_->Write32(0, IMC, 0xffffffff);
        dev_->Write32(0, EIMC, 0xffffffff);
    }

    void ResetDevice() {
        dev_->WriteBit32(0, CTRL, CTRL_RST, 1);
        usleep(1000);
        dev_->WaitBit32(0, STATUS, STATUS_PFRSTDONE, 1);
    }

    void SetLinkup() {
        dev_->WriteBit32(0, CTRL, CTRL_SLU, 1);
        printf("Waiting linkup...\n");
        dev_->WaitBit32(0, STATUS, STATUS_LU, 1);
    }

    template <typename R, typename T> R *skip(T *p, uint64_t how_many_Ts_to_skip) {
        return reinterpret_cast<R *>(reinterpret_cast<uint64_t>(p) +
                                     sizeof(T) * how_many_Ts_to_skip);
    }

    Result<ResultVoid, std::string> IntstallDmaMapping() {
        void *addr =
            mmap(0, kDmaSize, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
        if (addr == MAP_FAILED) {
            RAISE_ERRNO("mmap failed to allocate memory");
        }
        dma_memory_ = static_cast<char *>(addr);
        memset(dma_memory_, 0, kDmaSize);

        VALUE_OR_RAISE(dev_->RegisterDmaRegion(
            dma_memory_, reinterpret_cast<uint64_t>(dma_memory_), kDmaSize));

        printf("Mapped DMA region: VA=IOVA=%p, size=%#x\n", dma_memory_, kDmaSize);

        descriptor_ring_ = skip<AdvTxDataDescriptor>(dma_memory_, 0);
        ring_head_ = 0;
        ring_tail_ = 0;
        packet_hdr_ = skip<packet_header>(descriptor_ring_, kDescriptorRingSize);
        packet_payload_ = skip<char>(packet_hdr_, 1);

        return {};
    }

    void SetupTxRing() {
        // set ring addr
        dev_->Write64(0, TDBA64, reinterpret_cast<uint64_t>(descriptor_ring_));
        // set ring size
        dev_->Write32(0, TDLEN, kDescriptorRingSize * sizeof(AdvTxDataDescriptor));
        // set tail pointers
        dev_->Write32(0, TDH, 0);
        dev_->Write32(0, TDT, 0);
        // TXDCTL.ENABLE poll until 1
        dev_->WriteBit32(0, TXDCTL, TXDCTL_ENABLE, 1);
        dev_->WaitBit32(0, TXDCTL, TXDCTL_ENABLE, 1);
        // TCTL.EN
        dev_->WriteBit32(0, TCTL, TCTL_EN, 1);
    }

    void SendPacket(string payload) {
        auto set_ethaddr_array = [](uint64_t ethaddr, uint8_t *arr) {
            int i = 6;
            while (i-- > 0) {
                arr[i] = ethaddr & 0xffu;
                ethaddr >>= 8;
            }
        };

        if (payload.size() > kPacketBufferSize) {
            printf("payload too large\n");
            return;
        }

        printf("sending packet\n");
        // prepare data
        set_ethaddr_array(0xE24BD54A54A2, packet_hdr_->eth.h_dest);
        set_ethaddr_array(0xEA22CB41EF77, packet_hdr_->eth.h_source);
        packet_hdr_->eth.h_proto = htobe16(ETH_P_IPV6);

        packet_hdr_->ip6.ip6_flow = 0;
        packet_hdr_->ip6.ip6_vfc = 0x60;
        packet_hdr_->ip6.ip6_plen = htobe16(/*udp*/ 8 + payload.size());
        packet_hdr_->ip6.ip6_nxt = IPPROTO_UDP;
        packet_hdr_->ip6.ip6_hlim = 32;

        int success = 0;
        success += inet_pton(AF_INET6, "fd00::1", &packet_hdr_->ip6.ip6_src);
        success += inet_pton(AF_INET6, "fd00::2", &packet_hdr_->ip6.ip6_dst);
        if (success != 2) {
            printf("cannot set ipv6 address\n");
            return;
        }

        packet_hdr_->udp.uh_sport = htobe16(6200);
        packet_hdr_->udp.uh_dport = htobe16(6300);
        packet_hdr_->udp.uh_ulen = htobe16(8 + payload.size());

        strcpy(packet_payload_, payload.c_str());

        UdpChecksumer checker;
        checker.update(packet_hdr_->ip6.ip6_src);
        checker.update(packet_hdr_->ip6.ip6_dst);
        checker.update_le(8 + payload.size());
        checker.update_le(IPPROTO_UDP);
        checker.update(packet_hdr_->udp.uh_sport);
        checker.update(packet_hdr_->udp.uh_dport);
        checker.update(packet_hdr_->udp.uh_ulen);
        checker.update(payload.c_str(), (payload.size() + 1) / 2);
        packet_hdr_->udp.uh_sum = htobe16(checker.get());

        // set descriptor
        uint32_t tail_index = dev_->Read32(0, TDT);
        volatile auto &desc = descriptor_ring_[tail_index];

        desc.iova = reinterpret_cast<uint64_t>(packet_hdr_);
        desc.data_len = sizeof(packet_header) + payload.size();
        desc.dtyp = 3;
        desc.dcmd.end_of_packet = true;
        desc.dcmd.insert_fscs = true;
        desc.dcmd.report_status = true;
        desc.dcmd.descriptor_extension = false;

        dev_->Write32(0, TDT, tail_index + 1);
        printf("sending packet, descriptor=%d\n", tail_index);
        while (!desc.descriptor_done)
            ;
    }

  private:
    static const int kDmaSize = 32 * 1024;       // 32K
    static const int kDescriptorRingSize = 1024; // 1K entries, must be a multiple of 8
    static const int kPacketBufferSize = 1024;

    struct packet_header {
        ethhdr eth;  // 14
        ip6_hdr ip6; // 40
        udphdr udp;  // 8
    } __attribute__((packed));
    static_assert(sizeof(packet_header) == 62);

    VfioDevice *const dev_;

    char *dma_memory_ = nullptr;
    AdvTxDataDescriptor *descriptor_ring_ = nullptr;
    size_t ring_head_ = 0;
    size_t ring_tail_ = 0;
    packet_header *packet_hdr_ = nullptr;
    char *packet_payload_ = nullptr;

    static_assert((kDescriptorRingSize * sizeof(AdvTxDataDescriptor)) % 128 == 0);
    static_assert((kDescriptorRingSize * sizeof(AdvTxDataDescriptor)) +
                      sizeof(packet_header) + kPacketBufferSize <
                  kDmaSize);
};

Result<ResultVoid, std::string> run() {
    // absl::ParseCommandLine(argc, argv);
    VfioContainer container = VALUE_OR_RAISE(VfioContainer::Open());
    VALUE_OR_RAISE(container.AddIommuGroup(absl::GetFlag(FLAGS_group)));
    VALUE_OR_RAISE(container.SetIommuType1());
    VfioDevice device =
        VALUE_OR_RAISE(container.GetDeviceInGroup(absl::GetFlag(FLAGS_bdf)));

    if (!device.PrintDeviceInfo())
        return Err("Failed to print device info.");
    if (!device.PrintPciConfigSpace())
        return Err("Failed to print config space.");
    for (int bar = 0; bar < 8; bar++)
        device.PrintBarInfo(bar);

    // return {};

    IntelI211Device nic(&device);

    nic.MaskAllInterrupts();
    nic.ResetDevice();
    nic.MaskAllInterrupts();
    printf("Device reset done.\n");

    nic.SetPcieBusMaster();
    VALUE_OR_RAISE(nic.IntstallDmaMapping());

    nic.SetLinkup();
    printf("Link is up.\n");

    nic.SetupTxRing();

    while (true) {
        std::cout << "payload> " << std::flush;
        std::string payload;
        std::getline(std::cin, payload);
        if (payload == "exit")
            break;
        nic.SendPacket(payload);
    }

    return {};
}

int main(int argc, char *argv[]) {
    absl::ParseCommandLine(argc, argv);
    if (absl::GetFlag(FLAGS_bdf).empty() || absl::GetFlag(FLAGS_group).empty()) {
        std::cout << "missing required arg" << std::endl;
    } else {
        auto r = run();
        if (!r) {
            std::cout << r.Error() << std::endl;
        }
    }
}
