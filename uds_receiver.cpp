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

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, absl::GetFlag(FLAGS_uds_path).c_str(),
            sizeof(addr.sun_path) - 1);
    bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(fd, 16);
    std::cout << "listening..." << std::endl;
    int client = accept(fd, NULL, NULL);
    std::cout << "get client..." << std::endl;

    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    cmsghdr *cmsg = (cmsghdr *)cmsgbuf;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;

    char c = '\0';
    iovec vec = {};
    vec.iov_base = &c;
    vec.iov_len = sizeof(c);

    msghdr msg = {};
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg;
    msg.msg_controllen = CMSG_LEN(sizeof(int));

    int received = recvmsg(client, &msg, 0);
    printf("received=%d\n", received);

    int memfd = ((int *)CMSG_DATA(cmsg))[0];
    printf("memfd=%d\n", memfd);

    void *va = mmap(0, 4 * 1024 * 1024, PROT_WRITE | PROT_READ, MAP_SHARED, memfd, 0);
    printf("va=%p err=%s\n", va, strerror(errno));
    printf("memory content=%s\n", (char *)va);

    close(client);
    close(fd);
}
