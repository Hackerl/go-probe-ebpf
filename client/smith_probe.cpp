#include "smith_probe.h"
#include <aio/ev/timer.h>
#include <aio/net/stream.h>
#include <zero/log.h>

SmithProbe::SmithProbe(const aio::Context &context)
        : mContext(context), mChannel(std::make_shared<aio::sync::Channel<Trace, 100>>(context)) {
    zero::async::promise::loop<void>([=](const auto &loop) {
        transfer()->finally([=]() {
            LOG_INFO("disconnect");

            std::make_shared<aio::ev::Timer>(mContext)->setTimeout(std::chrono::minutes{1})->then([=] {
                LOG_INFO("reconnect");
                P_CONTINUE(loop);
            });
        });
    });
}

void SmithProbe::write(const Trace &trace) {
    mChannel->send(trace);
}

std::shared_ptr<zero::async::promise::Promise<void>> SmithProbe::transfer() {
    return aio::net::connect(mContext, "/tmp/smith_agent.sock")->then([=](const std::shared_ptr<aio::ev::IBuffer> &buffer) {
        return zero::async::promise::all(
                zero::async::promise::loop<void>([=](const auto &loop) {
                    buffer->read(4)->then([=](const std::vector<std::byte> &header) {
                        return buffer->read(ntohl(*(uint32_t *) header.data()));
                    })->then([=](const std::vector<std::byte> &message) {
                        LOG_INFO("message: %.*s", message.size(), message.data());
                        P_CONTINUE(loop);
                    })->fail([=](const zero::async::promise::Reason &reason) {
                        LOG_INFO("read buffer failed: %s", reason.message.c_str());
                        P_BREAK(loop);
                    });
                }),
                zero::async::promise::loop<void>([=](const auto &loop) {
                    mChannel->receive()->then([=](const Trace &trace) {
                        std::string message = nlohmann::json(SmithMessageEx{TRACE, trace}).dump(
                                -1,
                                ' ',
                                false,
                                nlohmann::json::error_handler_t::replace
                        );

                        uint32_t length = htonl(message.length());

                        buffer->write(&length, sizeof(uint32_t));
                        buffer->write(message);

                        return buffer->drain();
                    })->then([=]() {
                        P_CONTINUE(loop);
                    }, [=](const zero::async::promise::Reason &reason) {
                        LOG_INFO("write buffer failed: %s", reason.message.c_str());
                        P_BREAK(loop);
                    });
                })
        );
    });
}
