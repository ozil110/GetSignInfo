#include "DataSignInfo.hpp"

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		cout << "�����ļ�·��" << endl;
		return 0;
	}

	cout << L"�ļ���" << argv[1] << endl;

	string sign;
	BOOL b1 = DataSignInfo::getCertificateInfoFromPE(argv[1], sign);
	if (b1)
	{
		cout << "ǩ���ˣ�" << sign.c_str() << endl;
	}
	else
	{
		cout << "��ȡǩ��ʧ��" << endl;
	}
	//getchar();
	return 0;
}