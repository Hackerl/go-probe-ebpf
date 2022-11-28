#ifndef GO_PROBE_EBPF_SMITH_PROBE_H
#define GO_PROBE_EBPF_SMITH_PROBE_H

#include "smith_message.h"
#include <aio/sync/channel.h>

class SmithProbe {
public:
    explicit SmithProbe(const aio::Context &context);

public:
    void write(const Trace &trace);

private:
    std::shared_ptr<zero::async::promise::Promise<void>> transfer();

private:
    aio::Context mContext;
    std::shared_ptr<aio::sync::Channel<Trace, 100>> mChannel;
};

#endif //GO_PROBE_EBPF_SMITH_PROBE_H
