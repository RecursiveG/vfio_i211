#include "vfio.h"

#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "hw_defs.h"

#define CLOSE_THEN_RAISE_ERRNO(fd, msg)                                                  \
    do {                                                                                 \
        int e = errno;                                                                   \
        errno = 0;                                                                       \
        int r = close(fd);                                                               \
        int e2 = errno;                                                                  \
        std::stringstream ss;                                                            \
        ss << msg << " (errno=" << e << ", " << std::strerror(e) << ")";                 \
        if (r)                                                                           \
            ss << ", and failed to close fd " << fd << " (errno=" << e2 << ", "          \
               << std::strerror(e2) << ")";                                              \
        return Err(ss.str());                                                            \
    } while (false)

using std::string;

VfioDevice::VfioDevice(int container, int group, UniqueFd device)
    : container_(container), group_(group), device_(std::move(device)) {}
bool VfioDevice::PrintDeviceInfo() {
    vfio_device_info device_info{};
    device_info.argsz = sizeof(device_info);

    if (ioctl(device_.get(), VFIO_DEVICE_GET_INFO, &device_info) < 0) {
        perror("failed to get vfio device info");
        return false;
    }
    printf("device_info:\n  flags=%#x\n  num_regions=%d\n  num_irqs=%d\n",
           device_info.flags, device_info.num_regions, device_info.num_irqs);
    return true;
}
bool VfioDevice::PrintBarInfo(int bar) {
    auto reg_info = GetDeviceRegionInfo(bar);
    if (!reg_info)
        return false;
    printf("region %d info:\n  flags=%#x\n  cap_offset=%#x\n  size=%#llx\n  "
           "offset=%#llx\n",
           reg_info->index, reg_info->flags, reg_info->cap_offset, reg_info->size,
           reg_info->offset);
    return true;
}
bool VfioDevice::PrintPciConfigSpace() {
    auto bar7 = GetDeviceRegionInfo(VFIO_PCI_CONFIG_REGION_INDEX);
    if (!bar7)
        return false;
    PciConfigRegister pci_conf{};
    if (pread(device_.get(), &pci_conf, sizeof(pci_conf), bar7->offset) !=
        sizeof(pci_conf)) {
        perror("failed to read pcie config");
        return false;
    }
    printf("pci config space:\n"
           "  vendor_id=%#x\n"
           "  device_id=%#x\n"
           "  subsystem_vendor_id=%#x\n"
           "  subsystem_id=%#x\n"
           "  control_register=%#x\n"
           "  status_register=%#x\n"
           "  power_mgmt_cs=%#x\n",
           pci_conf.vendor_id, pci_conf.device_id, pci_conf.subsystem_vendor_id,
           pci_conf.subsystem_id, pci_conf.control_register, pci_conf.status_register,
           pci_conf.power_mgmt_cs);
    return true;
}

bool VfioDevice::PrintIrqsInfo() {
    vfio_device_info device_info{};
    device_info.argsz = sizeof(device_info);

    if (ioctl(device_.get(), VFIO_DEVICE_GET_INFO, &device_info) < 0) {
        perror("failed to get vfio device info");
        return false;
    }

    for (size_t i = 0; i < device_info.num_irqs; i++) {
        struct vfio_irq_info irq = {};
        irq.argsz = sizeof(irq);
        irq.index = i;

        if (ioctl(device_.get(), VFIO_DEVICE_GET_IRQ_INFO, &irq)) {
            perror("Failed to get irq info");
            return false;
        }
        printf("IRQ index %ld: flags=%#x, count=%d\n", i, irq.flags, irq.count);
    }
    return true;
}

std::optional<vfio_region_info> VfioDevice::GetDeviceRegionInfo(int region_idx) {
    vfio_region_info reg_info{};
    reg_info.argsz = sizeof(reg_info);
    reg_info.index = region_idx;
    int ret = ioctl(device_.get(), VFIO_DEVICE_GET_REGION_INFO, &reg_info);
    if (ret < 0) {
        perror(absl::StrCat("failed to get region info for region ", region_idx).c_str());
        return {};
    }
    return reg_info;
}

Result<char *, std::string> VfioDevice::MappedRegion(int bar, size_t *bar_size) {
    if (bar < 0 || bar > 5) {
        return Err(absl::StrCat("bar ", bar, " out of range, should in 0-5"));
    }
    if (bar_mapped_[bar]) {
        if (bar_size)
            *bar_size = bar_size_[bar];
        return bar_addr_[bar];
    }

    auto bar_info = GetDeviceRegionInfo(bar);
    if (!bar_info)
        return Err("Failed to get bar info");

    if (!(bar_info->flags & VFIO_REGION_INFO_FLAG_MMAP)) {
        return Err("bar cannot be mmaped");
    }
    if (bar_info->size <= 0) {
        return Err("bar not available");
    }
    void *addr =
        mmap(0, bar_info->size, PROT_READ | PROT_WRITE, MAP_SHARED, device_.get(),
             bar_info->offset); // !! MAP_SHARED !!
    if (addr == MAP_FAILED) {
        RAISE_ERRNO("mmap failed to map bar space");
    }
    std::cout << absl::StrFormat("mapped bar%d for device %d to address %p\n", bar,
                                 device_.get(), addr)
              << std::endl;

    bar_addr_[bar] = static_cast<char *>(addr);
    bar_size_[bar] = bar_info->size;
    bar_mapped_[bar] = true;
    if (bar_size)
        *bar_size = bar_info->size;
    return bar_addr_[bar];
}

char *VfioDevice::MappedRegionRaw(int bar) {
    auto r = MappedRegion(bar, nullptr);
    if (!r)
        return nullptr;
    return r.Value();
}

Result<ResultVoid, std::string> VfioDevice::RegisterDmaRegion(void *va, uint64_t iova,
                                                              uint64_t size) {
    vfio_iommu_type1_dma_map dma_map{};
    dma_map.argsz = sizeof(dma_map);
    dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;
    dma_map.vaddr = reinterpret_cast<uint64_t>(va);
    dma_map.iova = iova;
    dma_map.size = size;

    if (ioctl(container_, VFIO_IOMMU_MAP_DMA, &dma_map) < 0) {
        RAISE_ERRNO("failed to setup iommu dma mapping");
    }
    return {};
}

Result<int, std::string> VfioDevice::RegisterInterrupt(uint32_t index) {
    int fd = eventfd(0, 0);
    if (fd < 0)
        RAISE_ERRNO("Failed to create eventfd");
    constexpr size_t kReqSize = sizeof(vfio_irq_set) + sizeof(int32_t);
    vfio_irq_set *req = (vfio_irq_set *)malloc(kReqSize);
    req->argsz = kReqSize;
    req->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
    req->index = index;
    req->start = 0;
    req->count = 1;
    ((int32_t *)(req->data))[0] = fd;
    if (ioctl(device_.get(), VFIO_DEVICE_SET_IRQS, req)) {
        close(fd);
        free(req);
        return Err("Failed to set IRQ");
    }
    free(req);
    return fd;
}

void VfioDevice::UnmaskInterrupt(uint32_t index) {
    vfio_irq_set req = {};
    req.argsz = sizeof(req);
    req.flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_UNMASK;
    req.index = index;
    req.start = 0;
    req.count = 1;
    if (ioctl(device_.get(), VFIO_DEVICE_SET_IRQS, &req)) {
        std::cout << "Failed to unmask IRQ" << std::endl;
    }
}

void VfioDevice::TestInterrupt(uint32_t index) {
    vfio_irq_set req = {};
    req.argsz = sizeof(req);
    req.flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER;
    req.index = index;
    req.start = 0;
    req.count = 1;
    if (ioctl(device_.get(), VFIO_DEVICE_SET_IRQS, &req)) {
        std::cout << "Failed to test IRQ";
    }
}

uint32_t VfioDevice::Read32(int bar, uint64_t offset) {
    char *mapped_addr = MappedRegionRaw(bar) + offset;
    asm volatile("" ::: "memory");
    return *reinterpret_cast<volatile uint32_t *>(mapped_addr);
}
uint32_t VfioDevice::ReadShifted32(int bar, uint64_t offset, uint32_t mask) {
    uint32_t data = Read32(bar, offset);
    return (data & mask) / (mask & (~(mask - 1)));
}
void VfioDevice::Write32(int bar, uint64_t offset, uint32_t val) {
    char *mapped_addr = MappedRegionRaw(bar) + offset;
    asm volatile("" ::: "memory");
    *reinterpret_cast<volatile uint32_t *>(mapped_addr) = val;
}
void VfioDevice::WriteShifted32(int bar, uint64_t offset, uint32_t mask, uint32_t val) {
    uint32_t data = Read32(bar, offset);
    data = (((mask & (~(mask - 1))) * val) & mask) | (data & (~mask));
    Write32(bar, offset, data);
}

void VfioDevice::WriteBit32(int bar, uint64_t offset, uint32_t bit_index, int bit_set) {
    uint32_t val = Read32(bar, offset);
    if (bit_set) {
        val |= 1u << bit_index;
    } else {
        val &= ~(1u << bit_index);
    }
    Write32(bar, offset, val);
}

void VfioDevice::Wait32(int bar, uint64_t offset, uint32_t mask, uint32_t value) {
    while (true) {
        uint32_t val = Read32(bar, offset);
        if ((val & mask) == value)
            return;
        usleep(100);
    }
}
void VfioDevice::WaitBit32(int bar, uint64_t offset, uint32_t bit_index, int bit_val) {
    uint32_t b = bit_val ? 1 : 0;
    Wait32(bar, offset, 1u << bit_index, b << bit_index);
}
void VfioDevice::Write64(int bar, uint64_t offset, uint64_t val) {
    Write32(bar, offset, val & 0xffffffff);
    Write32(bar, offset + 4, val >> 32);
}

Result<VfioContainer, string> VfioContainer::Open() {
    int container = open("/dev/vfio/vfio", O_RDWR);
    if (container < 0) {
        RAISE_ERRNO("failed to open /dev/vfio/vfio");
    }
    if (ioctl(container, VFIO_GET_API_VERSION) != VFIO_API_VERSION) {
        CLOSE_THEN_RAISE_ERRNO(container, "Unknown VFIO API version");
    }
    if (!ioctl(container, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU)) {
        CLOSE_THEN_RAISE_ERRNO(container, "VFIO doesn't support IOMMU");
    }
    std::cout << "Opened new vfio container: " << container << std::endl;
    return VfioContainer(UniqueFd{container});
}

Result<ResultVoid, string> VfioContainer::AddIommuGroup(string group_name) {
    string group_file = absl::StrCat("/dev/vfio/", group_name);
    int group = open(group_file.c_str(), O_RDWR);
    if (group < 0) {
        RAISE_ERRNO(absl::StrCat("failed to open ", group_file));
    }

    vfio_group_status grp_status{};
    grp_status.argsz = sizeof(grp_status);
    int err = ioctl(group, VFIO_GROUP_GET_STATUS, &grp_status);
    if (err < 0) {
        CLOSE_THEN_RAISE_ERRNO(group, "failed to get VFIO group status");
    }
    if (!(grp_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
        CLOSE_THEN_RAISE_ERRNO(group, "group not viable");
    }
    std::cout << "Opened group: " << group << std::endl;

    if (ioctl(group, VFIO_GROUP_SET_CONTAINER, &container_fd_.ref()) < 0) {
        CLOSE_THEN_RAISE_ERRNO(group, "failed to set group's container");
    }

    int duplicated_groupd = dup(group);
    std::cout << "Duplicated_group: " << duplicated_groupd << std::endl;
    group_fd_ = UniqueFd(group);
    return {};
}

Result<ResultVoid, std::string> VfioContainer::SetIommuType1() {
    if (ioctl(container_fd_.get(), VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU) < 0) {
        return Err("cannot set iommu type");
    }
    std::cout << "IOMMU type set to TYPE1" << std::endl;
    return {};
}

Result<VfioDevice, string> VfioContainer::GetDeviceInGroup(string bdf) {
    int device = ioctl(group_fd_.get(), VFIO_GROUP_GET_DEVICE_FD, bdf.c_str());
    if (device < 0) {
        RAISE_ERRNO("failed to get device from group");
    }
    return VfioDevice(container_fd_.get(), group_fd_.get(), UniqueFd{device});
}

VfioContainer::VfioContainer(UniqueFd container_fd)
    : container_fd_(std::move(container_fd)) {}
