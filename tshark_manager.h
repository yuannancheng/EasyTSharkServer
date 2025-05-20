//
// Created by ync on 25-5-15.
//


#include "tshark_datatype.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "ip2region_util.h"
#include <loguru/loguru.hpp>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <sstream>
#include <iostream>
#include <fstream>
#include <thread>
#include <unordered_map>
#include <chrono>
#include <iomanip>
#include <ranges>
#include <set>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>


#ifdef _WIN32
typedef DWORD PID_T;
#else
typedef pid_t PID_T;
#endif


class TsharkManager
{
public:
    TsharkManager(const std::string& workDir);
    ~TsharkManager();

    // 分析数据包文件
    bool analysisFile(const std::string& filePath);

    // 打印所有数据包的信息
    void printAllPackets();

    // 获取指定编号数据包的十六进制数据
    bool getPacketHexData(uint32_t frameNumber, std::vector<unsigned char>& data);

    // 枚举网卡列表
    std::vector<AdapterInfo> getNetworkAdapters();

    // 开始抓包
    bool startCapture(std::string adapterName);

    // 停止抓包
    bool stopCapture();

private:
    // 解析每一行
    static bool parseLine(std::string line, const std::shared_ptr<Packet>& packet);

    // tshark程序路径
    std::string tsharkPath;

    // ip位置工具类
    IP2RegionUtil ip2RegionUtil;

    // 当前分析的文件路径
    std::string currentFilePath;

    // 分析得到的所有数据包信息，存储到哈希表，key是数据包ID，value是数据包信息指针，方便根据编号获取指定数据包信息
    std::unordered_map<uint32_t, std::shared_ptr<Packet>> allPackets;

    // 在线采集数据包的工作线程
    void captureWorkThreadEntry(std::string adapterName);

    // 在线分析线程
    std::shared_ptr<std::thread> captureWorkThread;

    // 是否停止抓包的标记
    bool stopFlag;

    // 在线抓包的tshark进程PID
    PID_T captureTsharkPid = 0;
};


// 自己封装一个能拿到进程PID的增强版popen函数
class ProcessUtil
{
public:
    // 跨平台的PopenEx
    static FILE* PopenEx(std::string command, PID_T* pidOut = nullptr);

    // 封装一个跨平台的杀进程函数
    static int Kill(PID_T pid);
};
