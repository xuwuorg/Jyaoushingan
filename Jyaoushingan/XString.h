#pragma once  
#include <string> 
#include <ostream>

/*
**  你需要自行补全XString类才能正常编译。
**  XString类是围绕着std::wstring进行封装的
**  最简单的方法是将XString替换为std::wstring
**/

class XString
{
public:
    XString();
    ~XString();

private:
    std::wstring str;
}; 