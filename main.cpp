#include <iostream>
#include <cstdio>
#include <sstream>
#include <fstream>
#include <vector>
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

// PCAP全局文件头
struct PcapHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

// 每一个数据报文前面的头
struct PacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t caplen;
    uint32_t len;
};

/**
 * 定义一个结构体，用来表示一个数据包
 */
struct Packet {
    int frame_number = 0;		// 数据包编号
    std::string timestamp;	    // 数据包的时间戳
    uint32_t cap_len = 0;       // 数据包长度
    std::string src_ip;			// 源IP地址
    int src_port = 0;		    // 源端口
    std::string dst_ip;			// 目的IP地址
    int dst_port = 0;		    // 目的端口
    std::string protocol;		// 协议
    std::string info;			// 数据包的概要信息
    uint32_t file_offset = 0;   // 数据包在文件中的存储偏移位置
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
    std::vector<std::string> fields; // 动态数组，用于临时存储

    // 字符串根据 tab 字符拆分成数组
    size_t start = 0, end;
    while ((end = line.find('\t', start)) != std::string::npos) {
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(line.substr(start)); // 添加最后一个子串

    // 字段顺序：
    // 0: frame.number
    // 1: frame.time
    // 2: frame.cap_len
    // 3: ip.src
    // 4: ipv6.src
    // 5: ip.dst
    // 6: ipv6.dst
    // 7: tcp.srcport
    // 8: udp.srcport
    // 9: tcp.dstport
    // 10: udp.dstport
    // 11: _ws.col.Protocol
    // 12: _ws.col.Info

    if (fields.size() >= 13) {
        packet.frame_number = std::stoi(fields[0]);
        packet.timestamp = fields[1];
        packet.cap_len = std::stoi(fields[2]);
        packet.src_ip = fields[3].empty() ? fields[4] : fields[3];
        packet.dst_ip = fields[5].empty() ? fields[6] : fields[5];
        if (!fields[7].empty() || !fields[8].empty()) {
            packet.src_port = std::stoi(fields[7].empty() ? fields[8] : fields[7]);
        }

        if (!fields[9].empty() || !fields[10].empty()) {
            packet.dst_port = std::stoi(fields[9].empty() ? fields[10] : fields[9]);
        }
        packet.protocol = fields[11];
        packet.info = fields[12];
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
    pktObj.AddMember("file_offset", packet.file_offset, allocator);
    pktObj.AddMember("cap_len", packet.cap_len, allocator);

    // 序列化为 JSON 字符串
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    pktObj.Accept(writer);

    // 打印JSON输出
    std::cout << buffer.GetString() << std::endl;
}

bool readPacketHex(const std::string& filePath, const uint32_t offset, const uint32_t length, std::vector<unsigned char> &buffer)
{
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        return false;
    }

    file.seekg(offset, std::ios::beg);
    if (!file) {
        return false;
    }

    // 先扩容，再写入报文数据
    buffer.resize(length);
    file.read(reinterpret_cast<char*>(buffer.data()), length);
    return true;
}

int main()
{
    const std::string packet_file = "/home/ync/Downloads/packets.pcap";
    const std::string command = "/usr/bin/tshark -r " + packet_file + " -T fields -e frame.number -e frame.time -e frame.cap_len -e ip.src -e ipv6.src -e ip.dst -e ipv6.dst -e tcp.srcport -e udp.srcport -e tcp.dstport -e udp.dstport -e _ws.col.Protocol -e _ws.col.Info";

    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe)
    {
        std::cerr << "Failed to run tshark command!" << std::endl;
        return 1;
    }

    std::vector<Packet> packets;
    char buffer[1024];
    // 当前处理的报文在文件中的偏移，第一个报文的偏移就是全局文件头24(也就是sizeof(PcapHeader))字节
    uint32_t file_offset = sizeof(PcapHeader);
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        Packet packet;
        parseLine(buffer, packet);

        // 计算当前报文的偏移，然后记录在Packet对象中
        packet.file_offset = file_offset + sizeof(PacketHeader);

        // 更新偏移游标
        file_offset = file_offset + sizeof(PacketHeader) + packet.cap_len;

        packets.push_back(packet); // 把所有的Packet对象，保存到一个vector容器中
    }

    // 使用C++11引入的新式for循环，通过auto关键字，让编译器自动推导其类型
    // 冒号后面跟一个数据容器，通过这种方式，可以来遍历这个容器中的每一项
    // 比通过传统的迭代器来遍历容器写法更加简洁
    for (auto &p : packets) {
        printPacket(p);

        // 读取这个报文的原始十六进制数据
        std::vector<unsigned char> hex_buffer;
        readPacketHex(packet_file, p.file_offset, p.cap_len, hex_buffer);

        // 打印读取到的数据：
        printf("Packet Hex: ");
        for (const unsigned char byte : hex_buffer) {
            printf("%02X ", byte);
        }
        printf("\n\n");
    }

    pclose(pipe);
    return 0;
}