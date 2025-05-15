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
    tsharkManager.analysisFile("/home/ync/_project/EasyTSharkServer/packets.pcap");

    tsharkManager.printAllPackets();


    return 0;
}
