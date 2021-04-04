#include <iostream>
#include <thread>

#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <pcap/pcap.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "hexdump.hpp"
#include "hw_defs.h"
#include "i211.h"
#include "pcap_dumper.h"
#include "result.h"
#include "vfio.h"

using namespace std;
using std::string;

ABSL_FLAG(string, bdf, "", "BUS:DEVICE:FUNCTION of the NIC.");
ABSL_FLAG(string, group, "", "IOMMU group number.");
ABSL_FLAG(string, pcap, "", "FIFO file to dump packets into.");

Result<ResultVoid, std::string> handle_interrupt(int interrupt_eventfd,
                                                 IntelI211Device &nic,
                                                 VfioMemory *rx_pkt_buf,
                                                 PcapDumperInterface *pcap) {
    static long counter = 0;
    uint64_t val;
    size_t len = read(interrupt_eventfd, &val, 8);
    if (len != 8) {
        return Err("Interrupt handler fd read failed");
    }
    uint32_t icr, eicr;
    // MSI is level trigger. Reading the ICR and EICR clears
    // the bits, which seems to reset the level.
    nic.ReadInterruptCause(&icr, &eicr);
    printf("INTERRUPT(%ld) ICR=%#x EICR=%#x\n", counter++, icr, eicr);
    if ((icr & 0x80) && (eicr & 1)) {
        int idx;
        uint16_t size;
        nic.RecvPacket(&idx, &size);
        printf("Received packet of %d bytes at %d\n", size, idx);
        pcap->Dump(std::string(rx_pkt_buf->data<char>() + 2048 * idx, size));
    }
    nic.UnmaskInterrupt();
    return {};
}

Result<ResultVoid, std::string> run() {
    // absl::ParseCommandLine(argc, argv);
    VfioContainer container = VALUE_OR_RAISE(VfioContainer::Open());
    VALUE_OR_RAISE(container.AddIommuGroup(absl::GetFlag(FLAGS_group)));
    VALUE_OR_RAISE(container.SetIommuType1());
    VfioDevice device =
        VALUE_OR_RAISE(container.GetDeviceInGroup(absl::GetFlag(FLAGS_bdf)));

    if (!device.PrintDeviceInfo())
        return Err("Failed to print device info.");
    if (!device.PrintIrqsInfo())
        return Err("Failed to print IRQ info.");
    if (!device.PrintPciConfigSpace())
        return Err("Failed to print config space.");
    for (int bar = 0; bar < 8; bar++)
        device.PrintBarInfo(bar);

    // return {};
    std::unique_ptr<PcapDumperInterface> pcap;
    if (absl::GetFlag(FLAGS_pcap) == "") {
        pcap = std::make_unique<PcapDummyDumper>();
    } else {
        pcap = std::make_unique<PcapDumper>(absl::GetFlag(FLAGS_pcap));
    }
    IntelI211Device nic(&device);

    nic.MaskAllInterrupts();
    nic.ResetDevice();
    nic.MaskAllInterrupts();
    printf("Device reset done.\n");

    int interrupt_eventfd = VALUE_OR_RAISE(nic.RegisterInterrupt());
    // nic.TestInterrupt();
    // printf("Testing interrupt.\n");
    nic.EnableLscInterrupt();
    printf("Enabled LCS interrupt\n");
    nic.EnableRx0Interrupt();
    printf("Enabled RxQ0 interrupt\n");

    nic.SetPcieBusMaster();
    ASSIGN_OR_RAISE(auto tx_ring_buf, VfioMemory::Allocate(1, &container));
    ASSIGN_OR_RAISE(auto rx_ring_buf, VfioMemory::Allocate(1, &container));
    ASSIGN_OR_RAISE(auto tx_pkt_buf, VfioMemory::Allocate(1, &container));
    ASSIGN_OR_RAISE(auto rx_pkt_buf, VfioMemory::Allocate(8, &container));
    NetworkPacket pkt(tx_pkt_buf->data(), tx_pkt_buf->iova(), tx_pkt_buf->size());

    nic.SetLinkup();
    nic.PrintRegisters();
    printf("Link is up.\n");

    VALUE_OR_RAISE(nic.SetupTxRing(std::move(tx_ring_buf), 8)); // 8 is minimal size
    VALUE_OR_RAISE(nic.SetupRxRing(std::move(rx_ring_buf), 8, rx_pkt_buf->iova(),
                                   rx_pkt_buf->size()));
    std::cout << "TX/RX queues ready" << std::endl;

    // Event loop start
    int epollfd = epoll_create(1024);
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = interrupt_eventfd;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, interrupt_eventfd, &ev);
    ev.data.fd = STDIN_FILENO;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev);

    struct epoll_event events_in[16];
    std::cout << "payload> " << std::flush;
    while (true) {
        int event_count = epoll_wait(epollfd, events_in, 16, -1);
        for (int i = 0; i < event_count; i++) {
            if (events_in[i].data.fd == STDIN_FILENO) {
                // Handles user input.
                std::string payload;
                std::getline(std::cin, payload);
                if (payload == "exit")
                    goto exit_event_loop;
                else if (payload == "status") {
                    nic.PrintRegisters();
                } else if (payload == "recv") {
                    int idx;
                    uint16_t size;
                    nic.RecvPacket(&idx, &size);
                    printf("Received packet of %d bytes at %d\n", size, idx);
                    hexdump(rx_pkt_buf->data<uint8_t>() + 2048 * idx, size, std::cout);
                    pcap->Dump(std::string(rx_pkt_buf->data<char>() + 2048 * idx, size));
                } else {
                    pkt.SetContent(payload);
                    pcap->Dump(pkt.dump());
                    nic.SendPacket(&pkt);
                }
                std::cout << "payload> " << std::flush;
            } else if (events_in[i].data.fd == interrupt_eventfd) {
                auto r = handle_interrupt(interrupt_eventfd, nic, rx_pkt_buf.get(),
                                          pcap.get());
                if (!r) {
                    std::cout << r.Error() << std::endl;
                }
            } else {
                std::cout << "unexpected fd";
            }
        }
    }
exit_event_loop:

    close(interrupt_eventfd);
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
