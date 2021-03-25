#include "i211.h"
#include "hw_defs.h"

// PCI Configuration space:COMMAND REG(0x4):bit #2
void IntelI211Device::SetPcieBusMaster() {
    int val;
    auto bar7 = dev_->GetDeviceRegionInfo(VFIO_PCI_CONFIG_REGION_INDEX);
    pread(dev_->device(), &val, 2, bar7->offset + 4);
    val |= 4;
    pwrite(dev_->device(), &val, 2, bar7->offset + 4);
}

void IntelI211Device::MaskAllInterrupts() {
    // Being lazy and just write all 1 s
    dev_->Write32(0, IMC, 0xffffffff);
    dev_->Write32(0, EIMC, 0xffffffff);
}

void IntelI211Device::EnableLscInterrupt() {
    // Clear any existing events
    dev_->WriteBit32(0, ICR, IMS_LSC, 1);
    dev_->WriteBit32(0, EICR, EIMS_OTHER, 1);
    // enable
    dev_->WriteBit32(0, IMS, IMS_LSC, 1);
    dev_->WriteBit32(0, EIMS, EIMS_OTHER, 1);
}

void IntelI211Device::ResetDevice() {
    dev_->WriteBit32(0, CTRL, CTRL_RST, 1);
    usleep(1000);
    dev_->WaitBit32(0, STATUS, STATUS_PFRSTDONE, 1);
}

void IntelI211Device::SetLinkup() {
    dev_->WriteBit32(0, CTRL, CTRL_SLU, 1);
    printf("Waiting linkup...\n");
    dev_->WaitBit32(0, STATUS, STATUS_LU, 1);
}

uint16_t IntelI211Device::ReadMdiRegister(int regaddr) {
    uint32_t val = (1u << 27) | ((regaddr & 0x1F) << 16);
    dev_->Write32(0, MDIC, val);
    dev_->WaitBit32(0, MDIC, MDIC_READY, 1);
    return dev_->Read32(0, MDIC) & 0xFFFF;
}

void IntelI211Device::PrintRegisters() {
#define PRINT_HEX(name)                                                                  \
    do {                                                                                 \
        uint32_t val = dev_->Read32(0, name);                                            \
        printf(#name ": %#x\n", val);                                                    \
    } while (0)
    uint32_t val = dev_->Read32(0, STATUS);
    reinterpret_cast<StatusRegister *>(&val)->dump("");
    PRINT_HEX(CTRL_EXT);
    PRINT_HEX(EIMS);
    PRINT_HEX(IMS);
    PRINT_HEX(GPIE);
    // 8.22.3.2
    printf("PHY:COPPER_CONTROL_REG: %#x\n", ReadMdiRegister(0));
}

Result<int, std::string> IntelI211Device::RegisterInterrupt() {
    dev_->UnmaskInterrupt(0);
    return dev_->RegisterInterrupt(0);
}

void IntelI211Device::UnmaskInterrupt() { dev_->UnmaskInterrupt(0); }

void IntelI211Device::TestInterrupt() { dev_->TestInterrupt(0); }

void IntelI211Device::ReadInterruptCause(uint32_t *icr, uint32_t *eicr) {
    *icr = dev_->Read32(0, ICR);
    *eicr = dev_->Read32(0, EICR);
}

template <typename R, typename T> R *skip(T *p, uint64_t how_many_Ts_to_skip) {
    return reinterpret_cast<R *>(reinterpret_cast<uint64_t>(p) +
                                 sizeof(T) * how_many_Ts_to_skip);
}

Result<ResultVoid, std::string>
IntelI211Device::SetupTxRing(std::unique_ptr<VfioMemory> desc_buf_ring,
                             size_t ring_entries) {
    uint64_t ring_size_bytes = ring_entries * sizeof(AdvTxDataDescriptor);
    if (ring_size_bytes % 128 != 0)
        return Err("Invalid ring_entries");
    if (ring_size_bytes > desc_buf_ring->size())
        return Err("Too large ring_entries");

    tx_desc_ring_ = std::move(desc_buf_ring);
    tx_desc_entries_ = ring_entries;
    // set ring addr
    dev_->Write64(0, TDBA64, tx_desc_ring_->iova());
    // set ring size
    dev_->Write32(0, TDLEN, ring_size_bytes);
    // set tail pointers
    dev_->Write32(0, TDH, 0);
    dev_->Write32(0, TDT, 0);
    // tx_desc_tail_ = 0;
    // TXDCTL.ENABLE poll until 1
    dev_->WriteBit32(0, TXDCTL, TXDCTL_ENABLE, 1);
    dev_->WaitBit32(0, TXDCTL, TXDCTL_ENABLE, 1);
    // TCTL.EN
    dev_->WriteBit32(0, TCTL, TCTL_EN, 1);

    return {};
}

void IntelI211Device::SendPacket(NetworkPacket *pkt) {
    // set descriptor
    uint32_t tail_index = dev_->Read32(0, TDT);
    volatile auto &desc = tx_desc_ring_->data<AdvTxDataDescriptor>()[tail_index];

    desc.iova = pkt->iova();
    desc.data_len = pkt->packet_size();
    desc.dtyp = 3;
    desc.dcmd.end_of_packet = true;
    desc.dcmd.insert_fscs = true;
    desc.dcmd.report_status = true;
    desc.dcmd.descriptor_extension = false;

    uint32_t new_tail = tail_index + 1;
    if (new_tail >= tx_desc_entries_)
        new_tail = 0;
    dev_->Write32(0, TDT, new_tail);
    printf("sending packet, tail advanced %d->%d\n", tail_index, new_tail);
    while (!desc.descriptor_done) {
    } // spin pool
}
