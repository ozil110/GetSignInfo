#pragma once
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/cms.h>
#include <openssl/cms/cms_lcl.h>
#include <openssl/err.h>
#include <sstream>
#include <vector>
using namespace std;

#define MAKE_PTR( cast, ptr, addValue ) (cast)( (DWORD_PTR)(ptr) + (DWORD_PTR)(addValue))

class DataSignInfo
{
public:
	
	static BOOL MatchDataSignFromPE(const char* path,const char* sign)
	{
		BOOL bMach = FALSE;
		int len = strlen(sign); //签名字符串长度
		std::ifstream file(path, std::ios::binary | std::ios::ate);
		if (!file.is_open()) {
			//std::cerr << "无法打开文件" << std::endl;
			return FALSE;
		}
		std::streamsize fileSize = file.tellg();
		file.seekg(0, std::ios::beg);
		if (file.fail()) {
			//std::cerr << "无法定位到PE头的签名部分" << std::endl;
			file.close();
			return FALSE;
		}

		char* strBuffer = NULL;
		strBuffer =  (char*) malloc((size_t)fileSize*sizeof(char));
		memset(strBuffer, 0, fileSize);
		if (!strBuffer) 
		{
			//std::cerr << "内存分配失败" << std::endl;
			file.close();
			return FALSE;
		}

		file.read(strBuffer, fileSize);

		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)strBuffer;
		PIMAGE_NT_HEADERS pNtHeaders = MAKE_PTR(PIMAGE_NT_HEADERS, pDosHeader, pDosHeader->e_lfanew);
		DWORD certTableRva = 0;
		DWORD certTableSize = 0;

		if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		{
			std::cout << "Win32" << std::endl;
			PIMAGE_OPTIONAL_HEADER32 header = (PIMAGE_OPTIONAL_HEADER32)&pNtHeaders->OptionalHeader;
			certTableRva = header->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
			certTableSize = header->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
		}
		else
		{
			std::cout << "x64" << std::endl;
			PIMAGE_OPTIONAL_HEADER64 header = (PIMAGE_OPTIONAL_HEADER64)&pNtHeaders->OptionalHeader;
			certTableRva = header->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
			certTableSize = header->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
		}
		free(strBuffer);
		strBuffer = NULL;

		file.seekg(certTableRva + 8, std::ios::beg);
		if (file.fail()) {
			//std::cerr << "无法定位到PE头的签名部分" << std::endl;
			file.close();
			return FALSE;
		}
		certTableSize =certTableSize- 8;
		strBuffer = (char*)malloc((size_t)certTableSize * sizeof(char));

		memset(strBuffer, 0, certTableSize);
		file.read(strBuffer, certTableSize);

		bMach = longest_common_substring(strBuffer, certTableSize, sign, len);

		free(strBuffer);
		strBuffer = NULL;
		file.close();
		return bMach;
	}


	static BOOL getCertificateInfoFromPE(const char* path,string& sign)
	{
		BOOL bMach = FALSE;
		std::ifstream file(path, std::ios::binary | std::ios::ate);
		if (!file.is_open()) {
			//std::cout << "无法打开文件" << std::endl;
			return FALSE;
		}
		std::streamsize fileSize = file.tellg();
		file.seekg(0, std::ios::beg);
		if (file.fail()) {
			//std::cerr << "无法定位到PE头的签名部分" << std::endl;
			file.close();
			return FALSE;
		}

		char* strBuffer = NULL;
		strBuffer =  (char*) malloc((size_t)fileSize*sizeof(char));
		memset(strBuffer, 0, fileSize);
		if (!strBuffer) 
		{
			//std::cerr << "内存分配失败" << std::endl;
			file.close();
			return FALSE;
		}

		file.read(strBuffer, fileSize);

		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)strBuffer;
		PIMAGE_NT_HEADERS pNtHeaders = MAKE_PTR(PIMAGE_NT_HEADERS, pDosHeader, pDosHeader->e_lfanew);
		DWORD certTableRva = 0;
		DWORD certTableSize = 0;

		if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		{
			std::cout << "Win32" << std::endl;
			PIMAGE_OPTIONAL_HEADER32 header = (PIMAGE_OPTIONAL_HEADER32)&pNtHeaders->OptionalHeader;
			certTableRva = header->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
			certTableSize = header->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
		}
		else
		{
			std::cout << "x64" << std::endl;
			PIMAGE_OPTIONAL_HEADER64 header = (PIMAGE_OPTIONAL_HEADER64)&pNtHeaders->OptionalHeader;
			certTableRva = header->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
			certTableSize = header->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
		}
		free(strBuffer);
		strBuffer = NULL;
		//没有签名
		if (certTableRva == 0||certTableSize == 0)
		{
			file.close();
			return TRUE;
		}

		file.seekg(certTableRva + 8, std::ios::beg);
		if (file.fail()) {
			file.close();
			return FALSE;
		}
		certTableSize =certTableSize - 8;
		strBuffer = (char*)malloc((size_t)certTableSize * sizeof(char));

		memset(strBuffer, 0, certTableSize);
		file.read(strBuffer, certTableSize);

		//新建BIO对象
		BIO* bio = BIO_new_mem_buf(strBuffer, certTableSize); 
		PKCS7* p7 = d2i_PKCS7_bio(bio,NULL);
		//释放BIO对象
		BIO_free(bio);  
		if (!p7) {
			printf("Error loading PKCS7 structure.\n");;
			return FALSE;
		}

		//获取X509
		STACK_OF(X509)* certs = PKCS7_get0_signers(p7, NULL, 0);
		if (sk_X509_num(certs) < 1) {
			printf("No signer certificate found.\n");
			PKCS7_free(p7);
			return FALSE;
		}

		X509* cert = sk_X509_value(certs, 0);
		sign = get_certificate_info(cert, NID_organizationName);

		PKCS7_free(p7);

		return TRUE;
	}

private:

	static char* get_certificate_info(X509* cert, int nid)
	{
		X509_NAME* subject_name = X509_get_subject_name(cert);
		int index = X509_NAME_get_index_by_NID(subject_name, nid, -1);
		X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject_name, index);
		ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
		return (char*)ASN1_STRING_data(data);
	}

    static BOOL longest_common_substring(const char *str1, int len1, const char* str2, int len2)
	{
		int m = len1;
		int n = len2;
		int max_len = 0;

		vector<vector<int>> dp(m + 1, vector<int>(n + 1));

		for (int i = 1; i <= m; ++i)
		{
			for (int j = 1; j <= n; ++j)
			{
				if (str1[i - 1] == str2[j - 1]) 
				{
					dp[i][j] = dp[i - 1][j - 1] + 1;
					if (dp[i][j] > max_len)
					{
						max_len = dp[i][j];
					}
					//new
					if(max_len == len2)
					{
						return TRUE;
					}
				} 
				else 
				{
					dp[i][j] = 0;
				}
			}
		}

		return FALSE;
	}
};