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
    tsharkManager.startCapture("wlp1s0");

    // 主线程进入命令等待停止抓包
    std::string input;
    while (true)
    {
        std::cout << "请输入q退出抓包: ";
        std::cin >> input;
        if (input == "q")
        {
            tsharkManager.stopCapture();
            break;
        }
    }

    // 打印所有捕获到的数据包信息
    tsharkManager.printAllPackets();

    // 列出网卡列表
    // std::vector<AdapterInfo> adaptors = tsharkManager.getNetworkAdapters();
    // for (auto item : adaptors) {
    //     LOG_F(INFO, "网卡[%d]: name[%s] remark[%s]", item.id, item.name.c_str(), item.remark.c_str());
    // }


    return 0;
}
