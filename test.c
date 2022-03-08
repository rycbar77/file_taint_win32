#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <windows.h>
#define true 0
#define false !true

int foo2(char a, char b, char c)
{
  a = 1;
  b = 2;
  c = 3;

  return 0;
}

int foo(char *buf)
{
  char c;
  char b;
  char a;

  c = buf[0];
  b = c;
  a = buf[8];

  foo2(a, b, c);

  return true;
}

int main(int ac, char **av)
{
  LPCTSTR lpPath = "./file.txt";
  PBYTE pData;
  DWORD dwSize = 32;
  DWORD dwErr = NO_ERROR;
  HANDLE hFile = CreateFile(lpPath, FILE_GENERIC_READ,                              //  打开文件，获得文件读句柄
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, //  共享方式打开，避免其他地方需要读写此文件
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

  if (INVALID_HANDLE_VALUE == hFile) //  文件打开失败，返回错误值
    return GetLastError();

  dwSize = GetFileSize(hFile, NULL);       //  取文件大小，这里的文件不能太大，否则需要分段读取文件
  pData = (PBYTE)LocalAlloc(LPTR, dwSize); //  申请缓冲区，下面的 ReadFile 里面会判断这里申请是否成功

  if (FALSE == ReadFile(hFile, pData, dwSize, &dwSize, NULL)) //  读取文件失败，记录失败错误值
    dwErr = GetLastError();

  CloseHandle(hFile); //  关闭文件句柄，避免句柄泄露
  foo(pData);
  HANDLE hConsoleOut = ::GetStdHandle(STD_OUTPUT_HANDLE);
  WriteFile(hConsoleOut, pData, strlen(pData), NULL, NULL);
  return dwErr;
}