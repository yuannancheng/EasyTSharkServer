#include <iostream>
#include <cstdio>
#include <sstream>
#include <vector>
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

/**
 * 定义一个结构体，用来表示一个数据包
 */
struct Packet {
    int frame_number = 0;		// 数据包编号
    std::string timestamp;		// 数据包的时间戳
    std::string src_ip;			// 源IP地址
    int src_port = 0;		    // 源端口
    std::string dst_ip;			// 目的IP地址
    int dst_port = 0;		    // 目的端口
    std::string protocol;		// 协议
    std::string info;			// 数据包的概要信息
};

/**
 * 针对输入的每一行，解析成为一个Packet结构体
 *
 * 解析的基本逻辑是这样的：tshark输出的每一行之间的多个字段，默认是使用tab符号来进行分隔的，所以解析的时候，通过tab把各个字段拆解开来。
 * 然后把所有拆解的字段保存到vector这个容器中，最后按照顺序赋值到Packet对象的各个字段。
 * @param line
 * @param packet
 */
void parseLine(std::string line, Packet& packet) {
    // 第二个参数使用的是引用，这是C++里面的用法，使用引用的好处是可以减少临时对象的创建以及对象之间的拷贝，提升性能。
    if (line.back() == '\n') {
        line.pop_back(); // 读取到的每一行结尾都有一个换行符，这里解析的时候，需要先将其剔除
    }
    // std::stringstream ss(line);
    // std::string field;
    std::vector<std::string> fields; // 动态数组，用于临时存储

    // 字符串根据 tab 字符拆分成数组
    size_t start = 0, end;
    while ((end = line.find('\t', start)) != std::string::npos) {
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(line.substr(start)); // 添加最后一个子串


    if (fields.size() >= 8) {
        try
        {
            packet.frame_number = std::stoi(fields[0]);
            packet.timestamp = fields[1];
            packet.src_ip = fields[2];
            packet.src_port = fields[3].empty() ? -1 : std::stoi(fields[3]);
            packet.dst_ip = fields[4];
            packet.dst_port = fields[5].empty() ? -1 : std::stoi(fields[5]);
            packet.protocol = fields[6];
            packet.info = fields[7];
        } catch (const std::exception& e) {
            printf("src_port: %s, dst_port: %s\n", fields[3].c_str(), fields[5].c_str());
            std::cerr << "Caught exception: " << e.what() << std::endl;
            std::exit(EXIT_FAILURE); // 等价于 return 1; in main
        }

    }
}

void printPacket(const Packet &packet) {
    // 构建JSON对象
    rapidjson::Document pktObj;
    rapidjson::Document::AllocatorType& allocator = pktObj.GetAllocator();

    // 设置JSON为Object对象类型
    pktObj.SetObject();

    // 添加JSON字段
    pktObj.AddMember("frame_number", packet.frame_number, allocator);
    // .c_str() 返回 const char*，因为 RapidJSON 的字符串构造需要 C 风格字符串。
    pktObj.AddMember("timestamp", rapidjson::Value(packet.timestamp.c_str(), allocator), allocator);
    pktObj.AddMember("src_ip", rapidjson::Value(packet.src_ip.c_str(), allocator), allocator);
    pktObj.AddMember("src_port", packet.src_port, allocator);
    pktObj.AddMember("dst_ip", rapidjson::Value(packet.dst_ip.c_str(), allocator), allocator);
    pktObj.AddMember("dst_port", packet.dst_port, allocator);
    pktObj.AddMember("protocol", rapidjson::Value(packet.protocol.c_str(), allocator), allocator);
    pktObj.AddMember("info", rapidjson::Value(packet.info.c_str(), allocator), allocator);

    // 序列化为 JSON 字符串
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    pktObj.Accept(writer);

    // 打印JSON输出
    std::cout << buffer.GetString() << std::endl;
}

int main()
{
    const char* command = "/usr/bin/tshark -r /home/ync/Downloads/packets.pcap -T fields -e frame.number -e frame.time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e _ws.col.Protocol -e _ws.col.Info";

    FILE* pipe = popen(command, "r");
    if (!pipe)
    {
        std::cerr << "Failed to run tshark command!" << std::endl;
        return 1;
    }

    std::vector<Packet> packets;
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        Packet packet;
        parseLine(buffer, packet);
        packets.push_back(packet); // 把所有的Packet对象，保存到一个vector容器中
    }

    // 使用C++11引入的新式for循环，通过auto关键字，让编译器自动推导其类型
    // 冒号后面跟一个数据容器，通过这种方式，可以来遍历这个容器中的每一项
    // 比通过传统的迭代器来遍历容器写法更加简洁
    for (auto &p : packets) {
        printPacket(p);
    }

    pclose(pipe);
    return 0;
}