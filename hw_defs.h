#ifndef VFIO_I211_HW_DEFS_H
#define VFIO_I211_HW_DEFS_H

#include <cinttypes>
#include <cstdio>
#include <magic_enum.hpp>
#include <string>

#define DUMP_HEX(var) printf("%s  " #var ": %#x\n", prefix.c_str(), var);
#define DUMP_BOOL(var)                                                                   \
    printf("%s  " #var ": %s\n", prefix.c_str(), (var ? "true" : "false"));
#define DUMP_ENUM(var)                                                                   \
    printf("%s  " #var ": %s\n", prefix.c_str(),                                         \
           std::string{magic_enum::enum_name(var)}.c_str());
#define DUMP(str) printf("%s%s\n", prefix.c_str(), str);

struct PciConfigRegister {
    // spec 9.2.2 table 9-2
    // mandatory pci register
    uint16_t vendor_id;
    uint16_t device_id;
    uint16_t control_register;
    uint16_t status_register;
    uint8_t revision_id;
    uint32_t class_code : 24;
    uint8_t cache_line_s;
    uint8_t lat_timer;
    uint8_t header_type;
    uint8_t bist;
    uint32_t bar_registers[6];
    uint32_t cardbus_cis_pointer;
    uint16_t subsystem_vendor_id;
    uint16_t subsystem_id;
    uint32_t expansion_rom_base_addr;
    uint8_t cap_ptr;
    uint32_t reserved : 24;
    uint32_t reserved2;
    uint8_t interrupt_line;
    uint8_t interrupt_pin;
    uint8_t min_grant;
    uint8_t max_latency;

    // power mgmt capability
    uint8_t capability_id;
    uint8_t next_ptr;
    uint16_t power_mgmt_caps;
    uint16_t power_mgmt_cs;
    uint8_t bridge_support_ext;
    uint8_t data;
} __attribute__((packed));
static_assert(sizeof(PciConfigRegister) == 0x48);

struct StatusRegister {
    // spec 8.2.2
    enum LinkSpeed { k10M = 0, k100M, k1000M, k1000M_2 };
    bool full_duplex : 1;
    bool link_up : 1;
    uint8_t reserved : 2;
    bool tx_off : 1;
    uint8_t reserved2 : 1;
    LinkSpeed link_speed : 2;
    uint8_t auto_speed_detect : 2;
    bool phy_ra : 1;
    uint8_t reserved3 : 8;
    bool gio_master_en : 1;
    bool dev_rst_set : 1;
    bool pf_rst_done : 1;
    uint16_t reserved4 : 9;
    bool mac_clock_gating_en : 1;
    void dump(std::string prefix) {
        DUMP("StatusRegister {");
        DUMP_BOOL(full_duplex);
        DUMP_BOOL(link_up);
        DUMP_BOOL(tx_off);
        DUMP_ENUM(link_speed);
        DUMP_HEX(auto_speed_detect);
        DUMP_BOOL(phy_ra);
        DUMP_BOOL(gio_master_en);
        DUMP_BOOL(dev_rst_set);
        DUMP_BOOL(pf_rst_done);
        DUMP_BOOL(mac_clock_gating_en);
        DUMP("}");
    }
} __attribute__((packed));
static_assert(sizeof(StatusRegister) == 4);

struct dcmd_layout {
    // spec 7.2.2.3.5
    bool end_of_packet : 1; // EOP
    bool insert_fscs : 1;   // IFCS
    bool : 1;
    bool report_status : 1; // RS
    bool : 1;
    bool descriptor_extension : 1; // DEXT always set to true
    bool vlan_packet_enable : 1;   // VLE
    bool segmentation_enable : 1;  // TSE
};
static_assert(sizeof(dcmd_layout) == 1);

struct AdvTxDataDescriptor {
    // spec 7.2.2.3
    union {
        uint64_t iova;
        uint64_t dma_time_stamp;
    };
    uint16_t data_len;
    int : 2;
    int mac : 2;
    int dtyp : 4; // always set to 3
    dcmd_layout dcmd;
    // STA
    bool descriptor_done : 1;
    bool ts_stat : 1;
    int : 2;
    // STA end
    int idx : 3; // always 0 or 1
    int : 1;
    // POPTS
    bool ixsm : 1; // IP checksum
    bool txsm : 1; // L4 checksum
    int : 4;
    // POPTS end
    uint32_t payload_length : 18;
};
static_assert(sizeof(AdvTxDataDescriptor) == 16);

struct LegacyRxDescriptor {
    uint64_t buffer_addr;
    uint16_t length;
    uint16_t fragment_checksum;

    bool descriptor_done : 1;
    bool eop : 1;
    bool rsv : 1;
    bool vp : 1;
    bool udpcs : 1;
    bool l4cs : 1;
    bool ipcs : 1;
    bool pif : 1;

    uint8_t error_field;
    uint16_t vlan_tag;
};
static_assert(sizeof(LegacyRxDescriptor) == 16);

#undef DUMP
#undef DUMP_BOOL
#undef DUMP_ENUM
#undef DUMP_HEX

#endif // VFIO_I211_HW_DEFS_H
