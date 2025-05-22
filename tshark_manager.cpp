//
// Created by ync on 25-5-15.
//

#include "tshark_manager.h"
#include <iomanip>
#include "loguru/loguru.hpp"

// 传入工作路径workDir
TsharkManager::TsharkManager(const std::string& workDir)
{
    this->tsharkPath = "/usr/bin/tshark";
    const std::string xdbPath = workDir + "/lib/ip2region/ip2region.xdb";
    IP2RegionUtil::init(xdbPath);
}

TsharkManager::~TsharkManager()
{
    IP2RegionUtil::uninit();
}

bool TsharkManager::analysisFile(const std::string& filePath)
{
    const std::vector<std::string> tsharkArgs = {
        tsharkPath,
        "-r", filePath,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "frame.cap_len",
        "-e", "eth.src",
        "-e", "eth.dst",
        "-e", "ip.src",
        "-e", "ipv6.src",
        "-e", "ip.dst",
        "-e", "ipv6.dst",
        "-e", "tcp.srcport",
        "-e", "udp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
    };

    std::string command;
    for (const auto& arg : tsharkArgs)
    {
        command += arg;
        command += " ";
    }

    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe)
    {
        LOG_F(ERROR, "Failed to run tshark command!");
        return false;
    }

    char buffer[4096];

    // 当前处理的报文在文件中的偏移，第一个报文的偏移就是全局文件头24(也就是sizeof(PcapHeader))字节
    uint32_t file_offset = sizeof(PcapHeader);
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    {
        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        if (!parseLine(buffer, packet))
        {
            LOG_F(ERROR, "%s", buffer);
            assert(false);
        }

        // 计算当前报文的偏移，然后记录在Packet对象中
        packet->file_offset = file_offset + sizeof(PacketHeader);

        // 更新偏移游标
        file_offset = file_offset + sizeof(PacketHeader) + packet->cap_len;

        // 获取IP地理位置
        packet->src_location = IP2RegionUtil::getIpLocation(packet->src_ip);
        packet->dst_location = IP2RegionUtil::getIpLocation(packet->dst_ip);

        // 将分析的数据包插入保存起来
        allPackets.insert(std::make_pair<>(packet->frame_number, packet));
    }

    pclose(pipe);

    // 记录当前分析的文件路径
    currentFilePath = filePath;

    LOG_F(INFO, "分析完成，数据包总数：%lu", allPackets.size());

    return true;
}

bool TsharkManager::parseLine(std::string line, const std::shared_ptr<Packet>& packet)
{
    if (line.back() == '\n')
    {
        line.pop_back();
    }
    std::stringstream ss(line);
    std::string field;
    std::vector<std::string> fields;

    // 自己实现字符串拆分
    size_t start = 0, end;
    while ((end = line.find('\t', start)) != std::string::npos)
    {
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(line.substr(start)); // 添加最后一个子串

    // 字段顺序：
    // 0: frame.number
    // 1: frame.time_epoch
    // 2: frame.len
    // 3: frame.cap_len
    // 4: eth.src
    // 5: eth.dst
    // 6: ip.src
    // 7: ipv6.src
    // 8: ip.dst
    // 9: ipv6.dst
    // 10: tcp.srcport
    // 11: udp.srcport
    // 12: tcp.dstport
    // 13: udp.dstport
    // 14: _ws.col.Protocol
    // 15: _ws.col.Info

    if (fields.size() >= 16)
    {
        packet->frame_number = std::stoi(fields[0]);
        packet->time = fields[1];
        packet->len = std::stoi(fields[2]);
        packet->cap_len = std::stoi(fields[3]);
        packet->src_mac = fields[4];
        packet->dst_mac = fields[5];
        packet->src_ip = fields[6].empty() ? fields[7] : fields[6];
        packet->dst_ip = fields[8].empty() ? fields[9] : fields[8];
        if (!fields[10].empty() || !fields[11].empty())
        {
            packet->src_port = std::stoi(fields[10].empty() ? fields[11] : fields[10]);
        }

        if (!fields[12].empty() || !fields[13].empty())
        {
            packet->dst_port = std::stoi(fields[12].empty() ? fields[13] : fields[12]);
        }
        packet->protocol = fields[14];
        packet->info = fields[15];

        return true;
    }
    else
    {
        return false;
    }
}

// 格式化时间戳
std::string formatTimestamp(const std::string& timestampStr)
{
    double timestamp = std::stod(timestampStr); // 转换为 double 类型时间戳
    std::time_t seconds = static_cast<std::time_t>(timestamp);
    int microseconds = static_cast<int>((timestamp - seconds) * 1'000'000);

    std::tm tm_time = *std::localtime(&seconds); // 转换为本地时间结构

    std::ostringstream oss;
    oss << std::put_time(&tm_time, "%Y-%m-%d %H:%M:%S")
        << '.' << std::setw(6) << std::setfill('0') << microseconds;

    return oss.str();
}

void TsharkManager::printAllPackets()
{
    // 使用C++11引入的新式for循环，通过auto关键字，让编译器自动推导其类型
    // 冒号后面跟一个数据容器，通过这种方式，可以来遍历这个容器中的每一项
    // 比通过传统的迭代器来遍历容器写法更加简洁
    for (auto& pair : allPackets)
    {
        std::shared_ptr<Packet> packet = pair.second;

        // 构建JSON对象
        rapidjson::Document pktObj;
        rapidjson::Document::AllocatorType& allocator = pktObj.GetAllocator();
        pktObj.SetObject();

        pktObj.AddMember("frame_number", packet->frame_number, allocator);
        pktObj.AddMember("timestamp", rapidjson::Value(formatTimestamp(packet->time).c_str(), allocator), allocator);
        pktObj.AddMember("src_mac", rapidjson::Value(packet->src_mac.c_str(), allocator), allocator);
        pktObj.AddMember("dst_mac", rapidjson::Value(packet->dst_mac.c_str(), allocator), allocator);
        pktObj.AddMember("src_ip", rapidjson::Value(packet->src_ip.c_str(), allocator), allocator);
        pktObj.AddMember("src_location", rapidjson::Value(packet->src_location.c_str(), allocator), allocator);
        pktObj.AddMember("src_port", packet->src_port, allocator);
        pktObj.AddMember("dst_ip", rapidjson::Value(packet->dst_ip.c_str(), allocator), allocator);
        pktObj.AddMember("dst_location", rapidjson::Value(packet->dst_location.c_str(), allocator), allocator);
        pktObj.AddMember("dst_port", packet->dst_port, allocator);
        pktObj.AddMember("protocol", rapidjson::Value(packet->protocol.c_str(), allocator), allocator);
        pktObj.AddMember("info", rapidjson::Value(packet->info.c_str(), allocator), allocator);
        pktObj.AddMember("file_offset", packet->file_offset, allocator);
        pktObj.AddMember("cap_len", packet->cap_len, allocator);
        pktObj.AddMember("len", packet->len, allocator);

        // 序列化为 JSON 字符串
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        pktObj.Accept(writer);

        // 打印JSON输出
        LOG_F(INFO, "%s", buffer.GetString());
    }
}

bool TsharkManager::getPacketHexData(uint32_t frameNumber, std::vector<unsigned char>& data)
{
    // 获取指定编号数据包的信息
    if (allPackets.find(frameNumber) == allPackets.end())
    {
        LOG_F(ERROR, "找不到编号为 %d 的数据包", frameNumber);
        return false;
    }
    std::shared_ptr<Packet> packet = allPackets[frameNumber];

    std::ifstream file(currentFilePath, std::ios::binary);
    if (!file)
    {
        return false;
    }

    file.seekg(packet->file_offset, std::ios::beg);
    if (!file)
    {
        return false;
    }

    // 先扩容，再写入报文数据
    data.resize(packet->cap_len);
    file.read(reinterpret_cast<char*>(data.data()), packet->cap_len);
    return true;
}

std::vector<AdapterInfo> TsharkManager::getNetworkAdapters()
{
    // 需要过滤掉的虚拟网卡，这些不是真实的网卡。tshark -D命令可能会输出这些，把它过滤掉
    std::set<std::string> specialInterfaces = {
        "sshdump", "ciscodump", "udpdump", "randpkt", "nflog", "nfqueue", "dpauxmon", "wifidump"
    };


    // 枚举到的网卡列表
    std::vector<AdapterInfo> interfaces;

    const std::string command = tsharkPath + " -D";

    // 使用智能指针自动关闭
    std::unique_ptr<FILE, int(*)(FILE*)> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe)
    {
        throw std::runtime_error("Failed to run tshark command.");
    }

    char buffer[256] = {0};
    while (fgets(buffer, sizeof(buffer), pipe.get()) != nullptr)
    {
        std::string line(buffer);
        // 去掉末尾换行符
        if (!line.empty() && line.back() == '\n')
        {
            line.pop_back();
        }

        auto first = line.find(' ');
        if (first == std::string::npos)
        {
            continue;
        }

        int id = std::stoi(line.substr(0, first - 1));
        std::string interfaceName;
        std::string remark;
        auto second = line.find(' ', first + 1);
        if (second == std::string::npos)
        {
            // 只有2段,第二段就是名字
            interfaceName = line.substr(first + 1);
        }
        else
        {
            // 有三段，默认为unix输出，第二段为名字，第三段为备注名
            interfaceName = line.substr(first + 1, second - first - 1);
            remark = line.substr(second + 1);

            // 但假如第二段是 \ 开头，则是Windows输出，需要交换位置
            if (interfaceName.starts_with('\\'))
            {
                auto tempName = interfaceName;
                interfaceName = remark;
                remark = interfaceName;
            }
        }

        // 滤掉特殊网卡
        if (
            specialInterfaces.find(interfaceName) != specialInterfaces.end() ||
            specialInterfaces.find(remark) != specialInterfaces.end()
        )
        {
            continue;
        }

        // 清理第二段的前后括号
        remark = remark.starts_with('(') ? remark.erase(0, 1) : remark;
        if (remark.ends_with(')')) remark.pop_back();


        AdapterInfo adapterInfo;
        adapterInfo.name = interfaceName;
        adapterInfo.id = id;
        adapterInfo.remark = remark;

        interfaces.push_back(adapterInfo);
    }

    return interfaces;
}

// 开始抓包
bool TsharkManager::startCapture(std::string adapterName)
{
    LOG_F(INFO, "即将开始抓包，网卡：%s", adapterName.c_str());

    // 关闭停止标记
    stopFlag = false;

    // 启动抓包线程
    captureWorkThread = std::make_shared<std::thread>(&TsharkManager::captureWorkThreadEntry, this,
                                                      "\"" + adapterName + "\"");

    return true;
}

// 停止抓包
bool TsharkManager::stopCapture()
{
    LOG_F(INFO, "即将停止抓包");
    stopFlag = true;
    ProcessUtil::Kill(captureTsharkPid);
    captureWorkThread->join(); // 使用join方法等待抓包线程的退出，会阻塞当前线程

    return true;
}

void TsharkManager::captureWorkThreadEntry(std::string adapterName)
{
    std::string captureFile = "capture.pcap";
    std::vector<std::string> tsharkArgs = {
        tsharkPath,
        "-i", adapterName.c_str(),
        "-w", captureFile, // 默认将采集到的数据包写入到这个文件下
        "-F", "pcap", // 指定存储的格式为PCAP格式
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "frame.cap_len",
        "-e", "eth.src",
        "-e", "eth.dst",
        "-e", "ip.src",
        "-e", "ipv6.src",
        "-e", "ip.dst",
        "-e", "ipv6.dst",
        "-e", "tcp.srcport",
        "-e", "udp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
    };

    std::string command;
    for (auto arg : tsharkArgs)
    {
        command += arg;
        command += " ";
    }

    FILE* pipe = ProcessUtil::PopenEx(command.c_str(), &captureTsharkPid);
    if (!pipe)
    {
        LOG_F(ERROR, "Failed to run tshark command!");
        return;
    }

    char buffer[4096];

    // 当前处理的报文在文件中的偏移，第一个报文的偏移就是全局文件头24(也就是sizeof(PcapHeader))字节
    uint32_t file_offset = sizeof(PcapHeader);
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr && !stopFlag)
    {
        // 在线采集的时候过滤额外的信息
        std::string line = buffer;
        if (
            line.find("Capturing on") != std::string::npos ||
            line.find("packets captured") != std::string::npos
        )
        {
            continue;
        }

        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        if (!parseLine(buffer, packet))
        {
            LOG_F(ERROR, "%s", buffer);
            assert(false);
        }

        // 计算当前报文的偏移，然后记录在Packet对象中
        packet->file_offset = file_offset + sizeof(PacketHeader);

        // 更新偏移游标
        file_offset = file_offset + sizeof(PacketHeader) + packet->cap_len;

        // 获取IP地理位置
        packet->src_location = IP2RegionUtil::getIpLocation(packet->src_ip);
        packet->dst_location = IP2RegionUtil::getIpLocation(packet->dst_ip);

        // 将分析的数据包插入保存起来
        allPackets.insert(std::make_pair<>(packet->frame_number, packet));
    }

    pclose(pipe);

    // 记录当前分析的文件路径
    currentFilePath = captureFile;
}

void TsharkManager::clearFlowTrendData()
{
    adapterFlowTrendMapLock.lock();
    adapterFlowTrendMonitorMap.clear();
    adapterFlowTrendMapLock.unlock();
}


// 开始监控所有网卡流量统计数据
void TsharkManager::startMonitorAdaptersFlowTrend()
{
    // 函数进来后，先要获取锁，防止等会创建的其他监控线程访问这个map出问题。
    std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);

    clearFlowTrendData();
    adapterFlowTrendMonitorStartTime = time(nullptr);

    // 第一步：获取网卡列表
    std::vector<AdapterInfo> adapterList = getNetworkAdapters();

    // 第二步：每个网卡启动一个线程，统计对应网卡的数据
    for (auto adapter : adapterList)
    {
        // 准备一个AdapterMonitorInfo对象，放到类的adapterFlowTrendMonitorMap成员中。
        adapterFlowTrendMonitorMap.insert(std::make_pair<>(adapter.name, AdapterMonitorInfo()));
        AdapterMonitorInfo& monitorInfo = adapterFlowTrendMonitorMap.at(adapter.name);

        // 创建一个线程，在这个线程中完成对这个网卡的流量数据监控。
        // 把线程指针保存到刚刚准备的AdapterMonitorInfo对象中。
        monitorInfo.monitorThread = std::make_shared<std::thread>(&TsharkManager::adapterFlowTrendMonitorThreadEntry,
                                                                  this, adapter.name);
        if (monitorInfo.monitorThread == nullptr)
        {
            LOG_F(ERROR, "监控线程创建失败，网卡名：%s", adapter.name.c_str());
        }
        else
        {
            LOG_F(INFO, "监控线程创建成功，网卡名：%s，monitorThread: %p", adapter.name.c_str(), monitorInfo.monitorThread.get());
        }
    }
}

// 停止监控所有网卡流量统计数据
void TsharkManager::stopMonitorAdaptersFlowTrend()
{
    std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);

    // 先杀死对应的tshark进程
    for (auto adapterPipePair : adapterFlowTrendMonitorMap)
    {
        ProcessUtil::Kill(adapterPipePair.second.tsharkPid);
    }

    // 然后关闭管道
    for (auto adapterPipePair : adapterFlowTrendMonitorMap)
    {
        // 然后关闭管道
        pclose(adapterPipePair.second.monitorTsharkPipe);

        if (adapterPipePair.second.monitorThread == nullptr)
        {
            LOG_F(ERROR, "发现监控线程nullptr，网卡名：%s", adapterPipePair.first.c_str());
            continue;
        }

        // 最后等待对应线程退出
        adapterPipePair.second.monitorThread->join();

        LOG_F(INFO, "网卡：%s 流量监控已停止", adapterPipePair.first.c_str());
    }

    // 清空记录的流量趋势数据
    adapterFlowTrendMonitorMap.clear();
}

// 获取所有网卡流量统计数据
void TsharkManager::getAdaptersFlowTrendData(std::map<std::string, std::map<long, long>>& flowTrendData)
{
    long timeNow = time(nullptr);

    // 数据从最左边冒出来
    // 一开始：以最开始监控时间为左起点，终点为未来300秒
    // 随着时间推移，数据逐渐填充完这300秒
    // 超过300秒之后，结束节点就是当前，开始节点就是当前-300
    long startWindow = timeNow - adapterFlowTrendMonitorStartTime > 300
                           ? timeNow - 300
                           : adapterFlowTrendMonitorStartTime;
    long endWindow = timeNow - adapterFlowTrendMonitorStartTime > 300
                         ? timeNow
                         : adapterFlowTrendMonitorStartTime + 300;

    adapterFlowTrendMapLock.lock();
    for (auto adapterPipePair : adapterFlowTrendMonitorMap)
    {
        flowTrendData.insert(std::make_pair<>(adapterPipePair.first, std::map<long, long>()));

        // 从当前时间戳向前倒推300秒，构造map
        for (long t = startWindow; t <= endWindow; t++)
        {
            // 如果trafficPerSecond中存在该时间戳，则使用已有数据；否则填充为0
            if (adapterPipePair.second.flowTrendData.find(t) != adapterPipePair.second.flowTrendData.end())
            {
                flowTrendData[adapterPipePair.first][t] = adapterPipePair.second.flowTrendData.at(t);
            }
            else
            {
                flowTrendData[adapterPipePair.first][t] = 0;
            }
        }
    }

    adapterFlowTrendMapLock.unlock();
}

// 获取指定网卡的流量趋势数据
void TsharkManager::adapterFlowTrendMonitorThreadEntry(std::string adapterName)
{
    if (adapterFlowTrendMonitorMap.find(adapterName) == adapterFlowTrendMonitorMap.end())
    {
        return;
    }

    char buffer[256] = {0};
    std::map<long, long>& trafficPerSecond = adapterFlowTrendMonitorMap[adapterName].flowTrendData;

    // Tshark命令，指定网卡，实时捕获时间戳和数据包长度
    std::string tsharkCmd = tsharkPath + " -i \"" + adapterName + "\" -T fields -e frame.time_epoch -e frame.len";

    LOG_F(INFO, "启动网卡流量监控: %s", tsharkCmd.c_str());

    PID_T tsharkPid = 0;
    FILE* pipe = ProcessUtil::PopenEx(tsharkCmd.c_str(), &tsharkPid);
    if (!pipe)
    {
        throw std::runtime_error("Failed to run tshark command.");
    }

    // 将管道保存起来
    // 此处是否有必要加锁？
    adapterFlowTrendMapLock.lock();
    adapterFlowTrendMonitorMap[adapterName].monitorTsharkPipe = pipe;
    adapterFlowTrendMonitorMap[adapterName].tsharkPid = tsharkPid;
    adapterFlowTrendMapLock.unlock();

    // 逐行读取tshark输出
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    {
        std::string line(buffer);
        std::istringstream iss(line); // 用字符串初始化流
        std::string timestampStr, lengthStr;

        if (line.find("Capturing") != std::string::npos || line.find("captured") != std::string::npos)
        {
            continue;
        }

        // 从流中提取数据：解析每行的时间戳和数据包长度
        if (!(iss >> timestampStr >> lengthStr))
        {
            continue;
        }

        try
        {
            // 直接用 std::stol 遇到小数会报错
            long timestamp = static_cast<long>(std::stod(timestampStr)); // 转换时间戳为long类型，秒数部分

            // 转换数据包长度为long类型
            long packetLength = std::stol(lengthStr);

            // 每秒的字节数累加
            trafficPerSecond[timestamp] += packetLength;

            // 如果trafficPerSecond超过300秒，则删除最早的数据，始终只存储最近300秒的数据
            while (trafficPerSecond.size() > 300)
            {
                // 访问并删除最早的时间戳数据
                auto it = trafficPerSecond.begin();
                LOG_F(INFO, "Removing old data for second: %ld, Traffic: %ld bytes", it->first, it->second);
                trafficPerSecond.erase(it);
            }
        }
        catch (const std::exception& e)
        {
            // 处理转换错误
            LOG_F(ERROR, "Error parsing tshark output: %s", line.c_str());
        }
    }

    LOG_F(INFO, "adapterFlowTrendMonitorThreadEntry 已结束");
}
