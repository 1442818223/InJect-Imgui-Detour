#define _CRT_SECURE_NO_WARNINGS
#include <string.h>
#include"pch.h"
#include"LoadDriver.h"
#include"api.h"
char AZTable[62] =
{
	0,
};

void initTable()
{
	if (AZTable[0] != 0) return;
	int k = 0;
	for (char i = 'A'; i <= 'Z'; i++, k++)
	{
		AZTable[k] = i;
	}

	for (char i = 'a'; i <= 'z'; i++, k++)
	{
		AZTable[k] = i;
	}

	for (char i = '0'; i <= '9'; i++, k++)
	{
		AZTable[k] = i;
	}
}

char* GetRandName()
{
	static char* name = NULL;
	if (name) return name;

	initTable();

	name = (char*)malloc(20);

	memset(name, 0, 20);  //15 .sys /0

	time_t t = time(NULL);
	srand(t);

	int len = (rand() % 10) + 5;
	for (int i = 0; i < len; i++)
	{
		int index = rand() % sizeof(AZTable);
		name[i] = AZTable[index];
	}
#pragma warning(disable:4996)
	strcat(name, ".sys");

	return name;
}

char* GetRandServiceName()
{
	static char* name = NULL;
	if (name) return name;          //两次调用 GetRandServiceName 函数生成的 char* 会一致

	initTable();

	name = (char*)malloc(10);

	memset(name, 0, 10);  //15 .sys 0

	time_t t = time(NULL);
	srand(t);

	int len = (rand() % 4) + 5;
	for (int i = 0; i < len; i++)
	{
		int index = rand() % sizeof(AZTable);
		name[i] = AZTable[index];
	}

	return name;
}

extern char* serviceName= NULL;
//cdcel __stdcall
BOOLEAN WINAPI SH_DriverLoad()   //驱动名字随机化，服务名随机
{
	LoadDriver Load;
	char bufPath[MAX_PATH] = { 0 };
	GetTempPathA(MAX_PATH, bufPath);

	char* driverName = GetRandName();
	serviceName = GetRandServiceName();
	
	strcat(bufPath, driverName);



	return Load.installDriver(bufPath, serviceName);
}

bool WINAPI SH_UnDriverLoad()
{
	LoadDriver Load;

	//char* serviceName = GetRandServiceName();

	return Load.unload(serviceName);
}