#ifndef GO_PROBE_EBPF_SMITH_MESSAGE_H
#define GO_PROBE_EBPF_SMITH_MESSAGE_H

#include <list>
#include <nlohmann/json.hpp>

enum Operate {
    EXIT,
    HEARTBEAT,
    TRACE,
    CONFIG,
    CONTROL,
    DETECT,
    FILTER,
    BLOCK,
    LIMIT
};

struct SmithMessage {
    Operate operate;
    nlohmann::json data;
};

struct SmithMessageEx : SmithMessage {
    pid_t pid;
    std::string version;
};

struct Heartbeat {
    std::string filter;
};

struct Request {
    std::string method;
    std::string uri;
    std::string host;
    std::string remote;
#ifndef DISABLE_HTTP_HEADER
    std::map<std::string, std::string> headers;
#endif
};

struct Trace {
    int classID;
    int methodID;
    std::list<std::string> args;
    std::list<std::string> stackTrace;
#ifdef ENABLE_HTTP
    Request request;
#endif
};

struct MatchRule {
    int index;
    std::string regex;
};

struct Filter {
    int classId;
    int methodID;
    std::list<MatchRule> include;
    std::list<MatchRule> exclude;
};

struct FilterConfig {
    std::string uuid;
    std::list<Filter> filters;
};

void to_json(nlohmann::json &j, const SmithMessageEx &message);
void from_json(const nlohmann::json &j, SmithMessage &message);

void to_json(nlohmann::json &j, const Heartbeat &heartbeat);
void to_json(nlohmann::json &j, const Request &request);
void to_json(nlohmann::json &j, const Trace &trace);

void from_json(const nlohmann::json &j, MatchRule &matchRule);
void from_json(const nlohmann::json &j, Filter &filter);
void from_json(const nlohmann::json &j, FilterConfig &config);

#endif //GO_PROBE_EBPF_SMITH_MESSAGE_H