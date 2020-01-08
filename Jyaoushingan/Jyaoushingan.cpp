// Eye Of the Evil King.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>
#include <windows.h>
#include "XJyaoushingan.h"
#include "resource.h"
#include <XString.h>

void showpe(XString& path)
{
    XJyaoushingan pec;
    //pec.set_file_path(path);
    pec.set_memory_buf((LPVOID)GetModuleHandle(NULL));
    if (!pec.open())
    {
        std::cout << "打开文件失败！" << std::endl;
        return  ;
    }
     
    if (!pec.is_mz())
    {
        std::cout << "MZ 获取失败！" << std::endl;
        return  ;
    }
    else
    {
        IMAGE_DOS_HEADER dos;
        pec.get_mz(dos);

        XMZStream mzs(dos); 
        XString str = mzs.to_string();
        std::cout << str.get_str().c_str() << std::endl;
    }
     
    if (!pec.is_pe())
    {
        std::cout << "PE 获取失败！" << std::endl;
        return  ;
    }
    else
    {
        std::cout << std::endl;

        IMAGE_FILE_HEADER file_head;
        pec.get_file_head(file_head);
        XFileHeadStream fhs(file_head);
        std::cout << fhs.to_string().get_str().c_str() << std::endl;

        if (pec.is_pe())
        {
            std::cout << "标准PE头" << std::endl;
        }
        else
        {
            std::cout << "非PE头" << std::endl;
            return  ;
        }

        IMAGE_OPTIONAL_HEADER option_head;
        pec.get_option_head(option_head);
        XOptionHeadStream ohs(option_head);
        std::cout << ohs.to_string().get_str().c_str() << std::endl;

        std::map<E_DATA_DIR_TABLE, IMAGE_DATA_DIRECTORY> data_dir;
        pec.get_data_dir(data_dir);
        XDataDirStream dds(data_dir);
        std::cout << dds.to_string().get_str().c_str() << std::endl;
         
        std::list<IMAGE_SECTION_HEADER> vt;
        if (!pec.get_section(vt))
        {
            std::cout << "节 获取失败！" << std::endl;
            return;
        }

        std::list<IMAGE_SECTION_HEADER>::iterator it = vt.begin();
        for (it; it != vt.end(); it++)
        {
            XSectionTableStream ss(*it);
            std::cout << ss.to_string(*it).get_str().c_str() << std::endl;
        }

        DWORD tmp = 0;
        pec.rva_mem2file(0x1234);
    }
}

void showimport(XString& file_path)
{ 
    XJyaoushingan pec;
    //pec.set_file_path(path);
    pec.set_memory_buf((LPVOID)GetModuleHandle(NULL));
    if (!pec.open())
    {
        std::cout << "打开文件失败！" << std::endl;
        return;
    }

    XIMPOTR_TABLE_DATA import_data;
    pec.get_importable(import_data);
     
}

void showexport(XString& file_path)
{
    XJyaoushingan pec;
    //pec.set_file_path(path);
    pec.set_memory_buf((LPVOID)GetModuleHandle(NULL));
    if (!pec.open())
    {
        std::cout << "打开文件失败！" << std::endl;
        return;
    }
     
    EXPORT_TABLE_DATA exportable;
    pec.get_exportable(exportable);
}

void relocation(XString& file_path)
{
    XJyaoushingan pec;
    //pec.set_file_path(path);
    pec.set_memory_buf((LPVOID)GetModuleHandle(NULL));
    if (!pec.open())
    {
        std::cout << "打开文件失败！" << std::endl;
        return;
    }
     
    std::list<XRELOCATION_DATA> relocation;
    pec.get_relocation(relocation);
}

void resource(XString& file_path)
{
    XJyaoushingan pec;
    //pec.set_file_path(file_path);
    pec.set_memory_buf((LPVOID)GetModuleHandle(NULL));
	if (!pec.open())
	{
		std::cout << "打开文件失败！" << std::endl;
		return;
	}

    std::list<XRESOURCE_DATA> list_data;
	pec.get_resource(list_data);
}

void delayimport(XString& file_path)
{
    XJyaoushingan pec;
    pec.set_file_path(file_path);
    //pec.set_memory_buf((LPVOID)GetModuleHandle(NULL));
    if (!pec.open())
    {
        std::cout << "打开文件失败！" << std::endl;
        return;
    }

    XDELAY_IMPORTABLE data;
    pec.get_delay_load_importable(data);
}

LONG WINAPI seh2(
    _In_ struct _EXCEPTION_POINTERS* ExceptionInfo
)
{
    MessageBox(0, L"222", 0, 0);
    return 0;
}

void threadload(const wchar_t* psz)
{ 
    XJyaoushingan pec;
    //pec.set_file_path(file_path);
    pec.set_memory_buf((LPVOID)GetModuleHandle(NULL));
    if (!pec.open())
    {
        std::cout << "打开文件失败！" << std::endl;
        return;
    }

    XTLS_DATA tls_data;
    pec.get_thread_local_storage(tls_data);
}

void fun2(const wchar_t* psz)
{
    SetUnhandledExceptionFilter(seh2);
    threadload(psz);
//     __try
//     {
//         threadload(psz);
//     }
//     __except (seh2(GetExceptionInformation()))
//     {
//         printf("222");
//     }
}

LONG WINAPI seh1(
    _In_ struct _EXCEPTION_POINTERS* ExceptionInfo
)
{
    MessageBox(0, L"111", 0, 0);
    return 0;
}
 
void loadconfig(const wchar_t* psz)
{ 
    XJyaoushingan pec;
    //pec.set_file_path(psz);
    pec.set_memory_buf((LPVOID)GetModuleHandle(NULL));
    if (!pec.open())
    {
        std::cout << "打开文件失败！" << std::endl;
        return;
    }

    XLOAD_CONFIG_TABLE tls_data;
    pec.get_load_config_table(tls_data);

    int dw = 10;
    int sz = 0;
    dw  /= sz;
}
 
void fun1(const wchar_t* psz)
{
//     SetUnhandledExceptionFilter(seh1); 
//     loadconfig(psz);
    __try
    { 
        loadconfig(psz);
    }
    __except (seh1(GetExceptionInformation()))
    {
        printf("1111");
    }
}

void NTAPI __stdcall TLS_CALLBACK(PVOID DllHandle, DWORD dwReason, PVOID Reserved) //DllHandle模块句柄、Reason调用原因、 Reserved加载方式（显式/隐式）
{
    XString str((DWORD)TLS_CALLBACK);
    switch (dwReason)
    {
    case DLL_THREAD_ATTACH:									//Reason会有4种参数
        MessageBox(0, L"TLS函数DLL_THREAD_ATTACH1", L"TLS", 0); break;
    case DLL_PROCESS_ATTACH:									//debug
        MessageBox(0, str.w_cstr(), L"TLS", 0); break;
    case DLL_THREAD_DETACH:
        MessageBox(0, L"TLS函数DLL_THREAD_DETACH1", L"TLS", 0); break;
    case DLL_PROCESS_DETACH:
        MessageBox(0, L"TLS函数DLL_PROCESS_DETACH1", L"TLS", 0); break;
    }

} 

void NTAPI __stdcall TLS_CALLBACK2(PVOID DllHandle, DWORD dwReason, PVOID Reserved) //DllHandle模块句柄、Reason调用原因、 Reserved加载方式（显式/隐式）
{
    switch (dwReason)
    {
    case DLL_THREAD_ATTACH:									//Reason会有4种参数
        MessageBox(0, L"TLS函数DLL_THREAD_ATTACH2", L"TLS", 0); break;
    case DLL_PROCESS_ATTACH:									//debug
        MessageBox(0, L"TLS函数DLL_PROCESS_ATTACH2", L"TLS", 0); break;
    case DLL_THREAD_DETACH:
        MessageBox(0, L"TLS函数DLL_THREAD_DETACH2", L"TLS", 0); break;
    case DLL_PROCESS_DETACH:
        MessageBox(0, L"TLS函数DLL_PROCESS_DETACH2", L"TLS", 0); break;
    }

}
  
//使用TLS需要在程序中新建一个data段专门存放TLS数据，
//并且需要通知链接器在PE头中添加相关数据，所以有了这一段代码
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")  

EXTERN_C

#pragma data_seg (".CRT$XLB")
//.CRT表明是使用C RunTime机制，$后面的XLB中：X表示随机的标识，L表示是TLS callback section，B可以被换成B到Y之间的任意一个字母，
//但是不能使用“.CRT$XLA”和“.CRT$XLZ”，因为“.CRT$XLA”和“.CRT$XLZ”是用于tlssup.obj的。
PIMAGE_TLS_CALLBACK _tls_callback[] = { TLS_CALLBACK, TLS_CALLBACK2,0 };
#pragma data_seg ()
 
 
int main(int argc, char* argv[])
{  

    if (argc < 2)
    {
        std::cout << "邪王真眼" << std::endl;
        std::cout << "邪王真眼.exe pe filepath" << std::endl; 
        std::cout << "邪王真眼.exe export filepath" << std::endl;
        std::cout << "邪王真眼.exe import filepath" << std::endl;
        std::cout << "邪王真眼.exe resource filepath" << std::endl;
        std::cout << "邪王真眼.exe certificate filepath" << std::endl;
        std::cout << "邪王真眼.exe relocation filepath" << std::endl;
        std::cout << "邪王真眼.exe debuginfo filepath" << std::endl;
        std::cout << "邪王真眼.exe globalpoint filepath" << std::endl;
        std::cout << "邪王真眼.exe threadload filepath" << std::endl;
        std::cout << "邪王真眼.exe loadconfig filepath" << std::endl;
        std::cout << "邪王真眼.exe boundimport filepath" << std::endl;
        std::cout << "邪王真眼.exe importaddress filepath" << std::endl;
        std::cout << "邪王真眼.exe delayimport filepath" << std::endl;
        //return 0;
    }   
     
    XString command(argv[1]);
    XString path(L"E:\\code\\邪王真眼\\XJyaoushingan\\Release\\1.exe");

    fun1(path.w_cstr());


    if (command == L"pe") 
        showpe(path); 
    else if (command == L"import") 
        showimport(path); 
    else if (command == L"export") 
        showexport(path); 
    else if (command == L"reload") 
        relocation(path);
    else if (command == L"resource")
        resource(path);
    else if (command == L"delayimport")
        delayimport(path);
    else if (command == L"threadload")
        fun2(path.w_cstr());
    else if (command == L"loadconfig")
        fun1(path.w_cstr());
	    
    return 0;
} 