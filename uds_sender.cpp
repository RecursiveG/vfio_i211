#include <cinttypes>
#include <iostream>

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"

using namespace std;
using std::string;

ABSL_FLAG(string, uds_path, "", "UDS path");

int main(int argc, char *argv[]) {
    absl::ParseCommandLine(argc, argv);
    if (absl::GetFlag(FLAGS_uds_path).empty()) {
        std::cout << "missing required arg" << std::endl;
        return 1;
    }
    string payload = "testing_Payload";

    int memfd = memfd_create("filebuffer", 0);
    printf("memfd=%d\n", memfd);
    int ret = ftruncate(memfd, 4 * 1024 * 1024); // 4MB
    printf("ret=%d err=%s\n", ret, strerror(errno));
    void *va = mmap(0, 4 * 1024 * 1024, PROT_WRITE | PROT_READ, MAP_SHARED, memfd, 0);
    printf("va=%p err=%s\n", va, strerror(errno));
    memcpy(va, payload.data(), payload.size());
    std::cout << "memfd ready" << endl;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, absl::GetFlag(FLAGS_uds_path).c_str(),
            sizeof(addr.sun_path) - 1);
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    std::cout << "uds_connected" << std::endl;

    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    cmsghdr *cmsg = (cmsghdr *)cmsgbuf;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    *(int *)CMSG_DATA(cmsg) = memfd;

    char c = '*';
    iovec vec = {};
    vec.iov_base = &c;
    vec.iov_len = sizeof(c);

    msghdr msg = {};
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg;
    msg.msg_controllen = CMSG_LEN(sizeof(int));

    int sent = sendmsg(fd, &msg, 0);
    printf("sent=%d\n", sent);

    close(memfd);
    close(fd);
}
