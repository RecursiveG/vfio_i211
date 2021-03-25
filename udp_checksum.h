#include <cinttypes>
#include <sys/types.h>

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