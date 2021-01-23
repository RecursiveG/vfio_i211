#pragma once

#include <iostream>
#include <linux/vfio.h>
#include <string>
#include <unistd.h>

#include "result.h"

class VfioContainer;
class VfioDevice;

class UniqueFd {
  public:
    UniqueFd() = default;
    explicit UniqueFd(int fd) : fd_(fd) {}
    ~UniqueFd() {
        if (fd_ >= 0) {
            close(fd_);
            std::cout << "closed fd " << fd_ << std::endl;
            fd_ = -1;
        }
    }
    UniqueFd(const UniqueFd &) = delete;
    UniqueFd &operator=(const UniqueFd &) = delete;
    UniqueFd(UniqueFd &&another) {
        this->fd_ = another.fd_;
        another.fd_ = -1;
    }
    UniqueFd &operator=(UniqueFd &&another) {
        if (&another == this)
            return *this;
        std::swap(this->fd_, another.fd_);
        return *this;
    }
    int get() { return fd_; }
    int &ref() { return fd_; }
    int release() {
        int ret = fd_;
        fd_ = -1;
        return ret;
    }

  private:
    int fd_ = -1;
};

class VfioDevice {
  public:
    // returns true if no error happened
    bool PrintDeviceInfo();
    bool PrintBarInfo(int bar);
    bool PrintPciConfigSpace();

    //
    std::optional<vfio_region_info> GetDeviceRegionInfo(int region_idx);

    Result<char *, std::string> MappedRegion(int bar, size_t *bar_size);

    int device() { return device_.get(); }

    Result<ResultVoid, std::string> RegisterDmaRegion(void *va, uint64_t iova,
                                                      uint64_t size);

    //
    // Register IO
    //
    uint32_t Read32(int bar, uint64_t offset);
    uint32_t ReadShifted32(int bar, uint64_t offset, uint32_t mask);
    void Write32(int bar, uint64_t offset, uint32_t val);
    void WriteShifted32(int bar, uint64_t offset, uint32_t mask, uint32_t val);
    // bit index in [31..0]
    void WriteBit32(int bar, uint64_t offset, uint32_t bit_index, int bit_set);
    // wait until BAR[OFFSET] & MASK == VALUE
    void Wait32(int bar, uint64_t offset, uint32_t mask, uint32_t value);
    // bit index in [31..0]
    void WaitBit32(int bar, uint64_t offset, uint32_t bit_index, int bit_val);
    // NOT atomic, split into two 32 bits writes.
    void Write64(int bar, uint64_t offset, uint64_t val);

    template <typename T> T read(int bar, uint64_t offset) {
        static_assert(sizeof(T) == 4);
        char buf[4];
        *reinterpret_cast<uint32_t *>(buf) = Read32(bar, offset);
        return *reinterpret_cast<T *>(buf);
    }

    template <typename T> void write(int bar, uint64_t offset, const T &val) {
        static_assert(sizeof(T) == 4);
        uint32_t v;
        memcpy(&v, &val, 4);
        Write32(bar, offset, v);
    }

  private:
    friend class VfioContainer;
    char *MappedRegionRaw(int bar);
    VfioDevice(int container, int group, UniqueFd device);
    int container_;
    int group_;
    UniqueFd device_;

    std::array<bool, 6> bar_mapped_ = {};
    std::array<char *, 6> bar_addr_ = {};
    std::array<uint64_t, 6> bar_size_ = {};
};

class VfioContainer {
  public:
    static Result<VfioContainer, std::string> Open();
    Result<ResultVoid, std::string> AddIommuGroup(std::string group_name);
    Result<ResultVoid, std::string> SetIommuType1();
    Result<VfioDevice, std::string> GetDeviceInGroup(std::string bdf);

  private:
    explicit VfioContainer(UniqueFd container_fd);
    UniqueFd container_fd_;
    UniqueFd group_fd_;
};