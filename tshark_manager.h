//
// Created by ync on 25-5-15.
//


#include "tshark_datatype.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "ip2region_util.h"
#include "process_util.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <sstream>
#include <iostream>
#include <fstream>
#include <thread>
#include <set>
#include <map>
#include <unordered_map>
#include <mutex>


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

    // 获取指定网卡的流量趋势数据
    void adapterFlowTrendMonitorThreadEntry(std::string adapterName);

    // 清空流量监控数据
    void clearFlowTrendData();

    // 开始监控所有网卡流量统计数据
    void startMonitorAdaptersFlowTrend();

    // 停止监控所有网卡流量统计数据
    void stopMonitorAdaptersFlowTrend();

    // 获取所有网卡流量统计数据
    void getAdaptersFlowTrendData(std::map<std::string, std::map<long, long>>& flowTrendData);

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

    // 网卡监控相关的信息
    class AdapterMonitorInfo
    {
    public:
        AdapterMonitorInfo()
        {
            monitorTsharkPipe = nullptr;
            tsharkPid = 0;
        }

        std::string adapterName; // 网卡名称
        std::map<long, long> flowTrendData; // 流量趋势数据
        std::shared_ptr<std::thread> monitorThread; // 负责监控该网卡输出的线程
        FILE* monitorTsharkPipe; // 线程与tshark通信的管道
        PID_T tsharkPid; // 负责捕获该网卡数据的tshark进程PID
    };

    // 后台流量趋势监控信息
    std::map<std::string, AdapterMonitorInfo> adapterFlowTrendMonitorMap;

    // 写上面流量趋势数据的锁
    // 这里使用的是recursive_mutex，可以递归获取的锁，就是说同一个线程可以多次加锁。
    // 如果使用非递归的std::mutex的话，如果一个线程之前已经获取了锁，
    // 在没有释放的时候，又来获取就会自己被自己锁住。建议使用可递归的锁。
    std::recursive_mutex adapterFlowTrendMapLock;

    // 开始抓包时间戳
    time_t adapterFlowTrendMonitorStartTime = 0;
};
