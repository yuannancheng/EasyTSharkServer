//
// Created by ync on 25-5-15.
//

#include "tshark_datatype.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "ip2region_util.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <sstream>
#include <iostream>
#include <fstream>
#include <unordered_map>



class TsharkManager {

public:
    TsharkManager(const std::string& workDir);
    ~TsharkManager();

    // 分析数据包文件
    bool analysisFile(const std::string& filePath);

    // 打印所有数据包的信息
    void printAllPackets();

    // 获取指定编号数据包的十六进制数据
    bool getPacketHexData(uint32_t frameNumber, std::vector<unsigned char> &data);

    // 枚举网卡列表
    std::vector<AdapterInfo> getNetworkAdapters();

private:
    // 解析每一行
    static bool parseLine(std::string line, const std::shared_ptr<Packet>& packet);

    std::string tsharkPath;
    IP2RegionUtil ip2RegionUtil;

    // 当前分析的文件路径
    std::string currentFilePath;

    // 分析得到的所有数据包信息，存储到哈希表，key是数据包ID，value是数据包信息指针，方便根据编号获取指定数据包信息
    std::unordered_map<uint32_t, std::shared_ptr<Packet>> allPackets;
};


