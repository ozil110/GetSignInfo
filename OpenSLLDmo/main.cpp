#include "DataSignInfo.hpp"

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		cout << "请输文件路径" << endl;
		return 0;
	}

	cout << L"文件：" << argv[1] << endl;

	string sign;
	BOOL b1 = DataSignInfo::getCertificateInfoFromPE(argv[1], sign);
	if (b1)
	{
		cout << "签名人：" << sign.c_str() << endl;
	}
	else
	{
		cout << "获取签名失败" << endl;
	}
	//getchar();
	return 0;
}