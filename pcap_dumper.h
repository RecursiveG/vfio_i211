#include <pcap/pcap.h>
#include <string>

class PcapDumperInterface {
  public:
    virtual void Dump(const std::string &data) = 0;
};

class PcapDummyDumper : public PcapDumperInterface {
  public:
    void Dump(const std::string &data) override {}
};

class PcapDumper : public PcapDumperInterface {
  public:
    explicit PcapDumper(const std::string &fifo);
    ~PcapDumper();
    void Dump(const std::string &data) override;

  private:
    pcap_t *pcap_;
    pcap_dumper_t *dumper_;
};