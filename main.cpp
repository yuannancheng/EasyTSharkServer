#include "tshark_manager.h"
#include <loguru/loguru.hpp>


void InitLog(int argc, char** argv)
{
    // 初始化 Loguru
    loguru::init(argc, argv);

    // 设置日志文件路径
    loguru::add_file("logs.txt", loguru::Append, loguru::Verbosity_MAX);
}

int main(int argc, char* argv[])
{
    // 设置控制台环境编码为UTF-8格式，防止打印输出的内容乱码
    setlocale(LC_ALL, "zh_CN.UTF-8");

    InitLog(argc, argv);

    TsharkManager tsharkManager("/home/ync/_project/EasyTSharkServer");

    // 启动监控
    tsharkManager.startMonitorAdaptersFlowTrend();

    // 睡眠10秒，等待监控网卡数据
    std::this_thread::sleep_for(std::chrono::seconds(10));

    // 读取监控到的数据
    std::map<std::string, std::map<long, long>> trendData;
    tsharkManager.getAdaptersFlowTrendData(trendData);

    // 停止监控
    tsharkManager.stopMonitorAdaptersFlowTrend();

    // 把获取到的数据打印输出
    rapidjson::Document resDoc;
    rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
    resDoc.SetObject();
    rapidjson::Value dataObject(rapidjson::kObjectType);
    for (const auto& adaptorItem : trendData)
    {
        rapidjson::Value adaptorDataList(rapidjson::kArrayType);
        for (const auto& timeItem : adaptorItem.second)
        {
            rapidjson::Value timeObj(rapidjson::kObjectType);
            timeObj.AddMember("time", (unsigned int)timeItem.first, allocator);
            timeObj.AddMember("bytes", (unsigned int)timeItem.second, allocator);
            adaptorDataList.PushBack(timeObj, allocator);
        }

        dataObject.AddMember(rapidjson::StringRef(adaptorItem.first.c_str()), adaptorDataList, allocator);
    }

    resDoc.AddMember("data", dataObject, allocator);

    // 序列化为 JSON 字符串
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    resDoc.Accept(writer);

    LOG_F(INFO, "网卡流量监控数据: %s", buffer.GetString());


    // 在线抓包指定网卡
    // tsharkManager.startCapture("docker0"); // wlp1s0

    // 主线程进入命令等待停止抓包
    // std::string input;
    // while (true)
    // {
    //     std::cout << "请输入q退出抓包: ";
    //     std::cin >> input;
    //     if (input == "q")
    //     {
    //         tsharkManager.stopCapture();
    //         break;
    //     }
    // }
    //
    // // 打印所有捕获到的数据包信息
    // tsharkManager.printAllPackets();

    return 0;
}
