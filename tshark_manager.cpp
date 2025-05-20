//
// Created by ync on 25-5-15.
//

#include "tshark_manager.h"

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
    std::set<std::string> specialInterfaces = {"sshdump", "ciscodump", "udpdump", "randpkt"};

    // 枚举到的网卡列表
    std::vector<AdapterInfo> interfaces;

    const std::string command = tsharkPath + " -D";

    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe)
    {
        throw std::runtime_error("Failed to run tshark command.");
    }

    char buffer[256] = {0};
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
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
            // 有三段,把最后一个拿到前面,中间的放到后面
            interfaceName = line.substr(second + 1);
            remark = line.substr(first + 1, second - first - 1);
        }

        // 滤掉特殊网卡
        if (
            specialInterfaces.find(interfaceName) != specialInterfaces.end() ||
            specialInterfaces.find(remark) != specialInterfaces.end()
        )
        {
            continue;
        }

        // 清理第一段的前后空格
        interfaceName = interfaceName.starts_with('(') ? interfaceName.erase(0, 1) : interfaceName;
        if (interfaceName.ends_with(')')) interfaceName.pop_back();

        // 假如第二段是 \ 开头,则是Windows输出,那么清空
        remark = remark.starts_with('\\') ? "" : remark;

        AdapterInfo adapterInfo;
        adapterInfo.name = interfaceName;
        adapterInfo.id = id;
        adapterInfo.remark = remark;

        interfaces.push_back(adapterInfo);
    }

    pclose(pipe);

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


#if defined(__unix__) || defined(__APPLE__)
// Linux/Mac平台实现PopenEx
FILE* ProcessUtil::PopenEx(std::string command, PID_T* pidOut)
{
    int pipefd[2] = {0};
    FILE* pipeFp = nullptr;

    if (pipe(pipefd) == -1)
    {
        perror("pipe");
        return nullptr;
    }

    pid_t pid = fork();
    if (pid == -1)
    {
        perror("fork");
        close(pipefd[0]);
        close(pipefd[1]);
        return nullptr;
    }

    if (pid == 0)
    {
        // 子进程
        // pid 等于 0 的部分已经是子进程执行了，从 fork() 处分叉出去2份代码互不干扰地执行
        close(pipefd[0]); // 关闭读端
        dup2(pipefd[1], STDOUT_FILENO); // 将 stdout 重定向到管道
        dup2(pipefd[1], STDERR_FILENO); // 将 stderr 重定向到管道
        close(pipefd[1]);

        execl("/bin/sh", "sh", "-c", command.c_str(), NULL); // 执行命令
        _exit(1); // execl失败
    }

    // 父进程将读取管道，关闭写端
    close(pipefd[1]);
    pipeFp = fdopen(pipefd[0], "r");

    if (pidOut)
    {
        *pidOut = pid;
    }

    return pipeFp;
}

// Linux/Mac平台实现杀死子进程方法
int ProcessUtil::Kill(PID_T pid)
{
    return kill(pid, SIGTERM);
}
#endif


#ifdef _WIN32
// Windows平台实现PopenEx
// 主要使用Win32的系统API函数CreatePipe创建管道，然后使用CreateProcess创建子进程。
FILE* ProcessUtil::PopenEx(std::string command, PID_T* pidOut = nullptr) {

    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES saAttr;
    PROCESS_INFORMATION piProcInfo;
    STARTUPINFO siStartInfo;
    FILE* pipeFp = nullptr;

    // 设置安全属性，允许管道句柄继承
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = nullptr;

    // 创建匿名管道
    if (!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
        perror("CreatePipe");
        return nullptr;
    }

    // 确保读句柄不被子进程继承
    if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
        perror("SetHandleInformation");
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return nullptr;
    }

    // 初始化 STARTUPINFO 结构体
    ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
    siStartInfo.cb = sizeof(STARTUPINFO);
    siStartInfo.hStdError = hWritePipe;
    siStartInfo.hStdOutput = hWritePipe;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    // 创建子进程
    if (!CreateProcess(
        nullptr,                        // No module name (use command line)
        (LPSTR)command.data(),          // Command line
        nullptr,                        // Process handle not inheritable
        nullptr,                        // Thread handle not inheritable
        TRUE,                           // Set handle inheritance
        CREATE_NO_WINDOW,               // No window
        nullptr,                        // Use parent's environment block
        nullptr,                        // Use parent's starting directory
        &siStartInfo,                   // Pointer to STARTUPINFO structure
        &piProcInfo                     // Pointer to PROCESS_INFORMATION structure
    )) {
        perror("CreateProcess");
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return nullptr;
    }

    // 关闭写端句柄（父进程不使用）
    CloseHandle(hWritePipe);

    // 返回子进程 PID
    if (pidOut) {
        *pidOut = piProcInfo.dwProcessId;
    }

    // 将管道的读端转换为 FILE* 并返回
    pipeFp = _fdopen(_open_osfhandle(reinterpret_cast<intptr_t>(hReadPipe), _O_RDONLY), "r");
    if (!pipeFp) {
        CloseHandle(hReadPipe);
    }

    // 关闭进程句柄（不需要等待子进程）
    CloseHandle(piProcInfo.hProcess);
    CloseHandle(piProcInfo.hThread);

    return pipeFp;
}

int ProcessUtil::Kill(PID_T pid) {

    // 打开指定进程
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess == nullptr) {
        std::cout << "Failed to open process with PID " << pid << ", error: " << GetLastError() << std::endl;
        return -1;
    }

    // 终止进程
    if (!TerminateProcess(hProcess, 0)) {
        std::cout << "Failed to terminate process with PID " << pid << ", error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return -1;
    }

    // 成功终止进程
    CloseHandle(hProcess);
    return 0;
}
#endif
