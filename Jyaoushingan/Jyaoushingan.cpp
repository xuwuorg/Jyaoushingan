// Eye Of the Evil King.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>
#include <windows.h>
#include "XJyaoushingan.h"
#include "resource.h"

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

    IMPOTR_TABLE_DATA import_data;
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
    XString path(L"E:\\code\\邪王真眼\\Eye Of the Evil King\\1.exe");

   // if (command == L"pe") 
        //showpe(path); 
   // else if (command == L"import") 
        //showimport(path); 
 //   else if (command == L"export") 
        //showexport(path); 
  //  else if (command == L"reload") 
        //relocation(path);
  //  else if (command == L"resource")
        resource(path);
	    
    return 0;
} 