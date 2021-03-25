#include "packet_builder.h"
#include "vfio.h"

class IntelI211Device {
  public:
    IntelI211Device(VfioDevice *dev) : dev_(dev) {}

    // 8.7.12 Interrupt Mask Clear
    static const uint64_t IMC = 0x150C;

    // 8.7.6 Extended Interrupt Mask Clear
    static const uint64_t EIMC = 0x1528;

    // 8.2.1 Device Control Register
    static const uint64_t CTRL = 0x0000;
    static const uint64_t CTRL_SLU = 6;  // Set Link Up
    static const uint32_t CTRL_RST = 26; // Port Software Reset

    // 8.2.2 Device Status Register
    static const uint64_t STATUS = 0x0008;
    static const uint32_t STATUS_PFRSTDONE = 21; // PF_RST_DONE
    static const uint32_t STATUS_LU = 1;         // Link Up

    // 8.2.3 Extended Device Control Register
    static const uint64_t CTRL_EXT = 0x0018;

    // 8.2.4 Media Dependent Interface Control Reg
    static const uint64_t MDIC = 0x0020;
    static const uint64_t MDIC_READY = 28; // Ready bit

    // 8.7.3 Extended Interrupt Cause Read
    static const uint64_t EICR = 0x1580;

    // 8.7.5 Extended Interrupt Mask Set Read Register
    static const uint64_t EIMS = 0x1524;
    static const uint64_t EIMS_OTHER = 31; // Need to check IMS

    // 8.7.9 Interrupt Cause Read
    static const uint64_t ICR = 0x1500;

    // 8.7.11 Interrupt Mask Set Read Register
    static const uint64_t IMS = 0x1508;
    static const uint64_t IMS_LSC = 2; // Link status change

    // 8.7.17 General Purpose Interrupt Enable
    static const uint64_t GPIE = 0x1514;

    // 8.9.1 Recv Control Register
    static const uint64_t RCTL = 0x0100;
    static const uint32_t RCTL_RXEN = 1;
    static const uint32_t RCTL_UPE = 3; // Unicast Promiscuous Enabled
    static const uint32_t RCTL_MPE = 4; // Multicast Promiscuous Enabled

    // 8.9.4-5 Recv Descriptor Base Addr LOW/HIGH[0]
    static const uint64_t RDBA64 = 0xC000;

    // 8.9.6 Recv Descriptor Ring Length[0]
    static const uint64_t RDLEN = 0xC008;

    // 8.9.7 Recv Descriptor Head[0]
    static const uint64_t RDH = 0xC010;

    // 8.9.8 Recv Descriptor Tail[0]
    static const uint64_t RDT = 0xC018;

    // 8.9.9 Recv Descript Control[0]
    static const uint64_t RXDCTL = 0xC028;
    static const uint32_t RXDCTL_ENABLE = 25;

    // 8.11.1 Transmit Control Register
    static const uint64_t TCTL = 0x0400;
    static const uint64_t TCTL_EN = 1; // Transmit enable

    // 8.11.10 8.11.11 Transmit Descriptor Base Address Low/High[0]
    static const uint64_t TDBA64 = 0xE000;

    // 8.11.12 Transmit Descriptor Ring Length[0], number of bytes
    static const uint64_t TDLEN = 0xE008;

    // 8.11.13 Transmit Descriptor Head[0]
    static const uint64_t TDH = 0xE010;

    // 8.11.14 Transmit Descriptor Tail[0]
    static const uint64_t TDT = 0xE018;

    // 8.11.15 Transmit Descriptor Control[0]
    static const uint64_t TXDCTL = 0xE028;
    static const uint32_t TXDCTL_ENABLE = 25; // Transmit Queue Enable

    // PCI Configuration space:COMMAND REG(0x4):bit #2
    void SetPcieBusMaster();
    void MaskAllInterrupts();
    void EnableLscInterrupt();
    void ResetDevice();
    void SetLinkup();
    uint16_t ReadMdiRegister(int regaddr);
    void PrintRegisters();
    Result<int, std::string> RegisterInterrupt();
    void UnmaskInterrupt();
    void TestInterrupt();
    void ReadInterruptCause(uint32_t *icr, uint32_t *eicr);

    Result<ResultVoid, std::string> SetupTxRing(std::unique_ptr<VfioMemory> desc_buf_ring,
                                                size_t ring_entries);
    Result<ResultVoid, std::string> SetupRxRing(std::unique_ptr<VfioMemory> desc_buf_ring,
                                                size_t ring_entries,
                                                uint64_t packet_buf_iova,
                                                uint64_t packet_buf_bytes);
    void SendPacket(NetworkPacket *pkt);
    void RecvPacket(int *index, uint16_t *length);

  private:
    VfioDevice *const dev_;

    std::unique_ptr<VfioMemory> tx_desc_ring_;
    size_t tx_desc_entries_; // # of AdvTxDataDescriptor
    // size_t tx_desc_tail_; // next available
    std::unique_ptr<VfioMemory> rx_desc_ring_;
    size_t rx_desc_head_; // next to complete
};