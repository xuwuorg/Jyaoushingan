#pragma once  
#include <string> 
#include <ostream>

/*
**  ����Ҫ���в�ȫXString������������롣
**  XString����Χ����std::wstring���з�װ��
**  ��򵥵ķ����ǽ�XString�滻Ϊstd::wstring
**/

class XString
{
public:
    XString();
    ~XString();

private:
    std::wstring str;
}; 