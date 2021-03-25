#include <iostream>
#include <thread>

#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "hexdump.hpp"
#include "hw_defs.h"
#include "i211.h"
#include "result.h"
#include "vfio.h"

using namespace std;
using std::string;

ABSL_FLAG(string, bdf, "", "BUS:DEVICE:FUNCTION of the NIC.");
ABSL_FLAG(string, group, "", "IOMMU group number");

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

    IntelI211Device nic(&device);

    nic.MaskAllInterrupts();
    nic.ResetDevice();
    nic.MaskAllInterrupts();
    printf("Device reset done.\n");

    std::atomic<bool> program_exit = false;
    int interrupt_eventfd = VALUE_OR_RAISE(nic.RegisterInterrupt());
    std::thread interrupt_handler([interrupt_eventfd, &nic, &program_exit]() {
        std::cout << "Interrupt handler started." << std::endl;
        uint64_t counter = 0;
        while (true) {
            uint64_t val;
            size_t len = read(interrupt_eventfd, &val, 8);
            if (program_exit) {
                std::cout << "Interrupt handler exits." << std::endl;
                return;
            }
            if (len != 8) {
                std::cout << "Interrupt handler fd read failed" << std::endl;
                return;
            }
            uint32_t icr, eicr;
            // MSI is level trigger. Reading the ICR and EICR clears
            // the bits, which seems to reset the level.
            nic.ReadInterruptCause(&icr, &eicr);
            printf("INTERRUPT(%ld) ICR=%#x EICR=%#x\n", counter++, icr, eicr);
            nic.UnmaskInterrupt();
        }
    });
    // nic.TestInterrupt();
    // printf("Testing interrupt.\n");
    nic.EnableLscInterrupt();
    printf("Enabled LCS interrupt\n");

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

    while (true) {
        std::cout << "payload> " << std::flush;
        std::string payload;
        std::getline(std::cin, payload);
        if (payload == "exit")
            break;
        else if (payload == "status") {
            nic.PrintRegisters();
        } else if (payload == "recv") {
            int idx;
            uint16_t size;
            nic.RecvPacket(&idx, &size);
            printf("Received packet of %d bytes at %d\n", size, idx);
            hexdump(rx_pkt_buf->data<uint8_t>() + 2048 * idx, size, std::cout);
        } else {
            pkt.SetContent(payload);
            nic.SendPacket(&pkt);
        }
    }
    program_exit = true;
    uint64_t one = 1;
    write(interrupt_eventfd, &one, 8);
    interrupt_handler.join();
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
