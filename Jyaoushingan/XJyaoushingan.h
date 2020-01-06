#pragma once
/************************************************************************************
**  Copyright 2018 ~ 2222 阿虚
**  blog: http://www.xuwu.org
**  mail: xuwuorg#163.com
**
**  文件名：XJyaoushingan.h
**  功能：Windows PE结构解析类
**
**  模块： XJyaoushingan
**
**  XJyaoushingan类：负责对文件或者内存解析PE结构的方法类
**  方法：
**      对文件解析PE格式需要用这个接口设置目标文件路径
**      void set_file_path(const XString& file_path);
**      对内存解析PE格式需要使用这个接口给与需要解析的模块基址
**      void set_memory_buf(LPVOID buf_head);
**
**      开始解析PE格式
**      bool open();
**      关闭当前设置的目标解析PE
**      void close();
**      接口函数返回false时可以通过这个函数来判断为什么出错
**      DWORD get_last_err();
**
**      得到PE的MZ头信息
**      bool get_mz(IMAGE_DOS_HEADER& mz);
**      判断这个文件(内存)是否是MZ文件格式
**      bool is_mz();
**      修改MZ头文件信息
**      bool set_mz(IMAGE_DOS_HEADER& mz);
**      得到PE头偏移地址
**      DWORD get_pe_offset();
**
**      判断是否是PE头
**      bool is_pe();
**      得到文件头结构体信息
**      bool get_file_head(IMAGE_FILE_HEADER& file_head);
**      修改文件头信息
**      bool set_file_head(IMAGE_FILE_HEADER& file_head);
**
**      得到选择头信息
**      bool get_option_head(IMAGE_OPTIONAL_HEADER& option_head);
**      修改选择头信息
**      bool set_option_head(IMAGE_OPTIONAL_HEADER& option_head);
**
**      获取指定的数据目录
**      bool get_data_dir(E_DATA_DIR_TABLE dd, IMAGE_DATA_DIRECTORY& data_dir);
**      得到所有数据目录
**      bool get_data_dir(std::map<E_DATA_DIR_TABLE, IMAGE_DATA_DIRECTORY>& data_dir);
**      修改数据目录表
**      bool set_data_dir(E_DATA_DIR_TABLE dd, IMAGE_DATA_DIRECTORY& data_dir);
**
**      是否有节
**      bool is_section();
**      得到节数量
**      DWORD get_section_count();
**      获取第i个节
**      bool get_section(DWORD index, IMAGE_SECTION_HEADER& section);
**      获取整个节
**      bool get_section(std::list<IMAGE_SECTION_HEADER>& section);
**      修改指定节
**      bool set_section(DWORD index, IMAGE_SECTION_HEADER& section);
**      负责虚拟地址转文件地址
**      DWORD rva_mem2file(DWORD address, PIMAGE_SECTION_HEADER section_head = NULL);
**
**      得到导入表信息
**      bool get_importable(IMPOTR_TABLE_DATA& import_data);
**      得到导出表信息
**      bool get_exportable(EXPORT_TABLE_DATA& exportable);
**      得到重定位表信息
**      bool get_relocation(std::list<XRELOCATION_DATA>& lrelocation);
**      得到资源信息
**      bool get_resource(std::list<XRESOURCE_DATA> data);
**      得到延迟加载导入表
**      bool get_delay_load_importable(XDELAY_IMPORTABLE& delay_importable);
**
**
***********                                                                ***********
**  模块： XXXXStream
**  XXXXStream类：主要是用于方便UI显示而封装的。
*/
  
// class XFileHeadStream;
// class XOptionHeadStream;
// class XDataDirStream;
// class XSectionTable;
// class XSectionTableStream; 
 
class XJyaoushingan;

#include <windows.h>
#include <XString.h>
#include <map>
#include <list>

//XP的WinNT.h尽然没有带结构体
typedef struct tagIMAGE_DELAYLOAD_DESCRIPTOR {
    union {
        DWORD AllAttributes;
        struct {
            DWORD RvaBased : 1;             // Delay load version 2
            DWORD ReservedAttributes : 31;
        } DUMMYSTRUCTNAME;
    } Attributes;

    DWORD DllNameRVA;                       // RVA to the name of the target library (NULL-terminate ASCII string)
    DWORD ModuleHandleRVA;                  // RVA to the HMODULE caching location (PHMODULE)
    DWORD ImportAddressTableRVA;            // RVA to the start of the IAT (PIMAGE_THUNK_DATA)
    DWORD ImportNameTableRVA;               // RVA to the start of the name table (PIMAGE_THUNK_DATA::AddressOfData)
    DWORD BoundImportAddressTableRVA;       // RVA to an optional bound IAT
    DWORD UnloadInformationTableRVA;        // RVA to an optional unload info table
    DWORD TimeDateStamp;                    // 0 if not bound,
                                            // Otherwise, date/time of the target DLL

} IMAGE_DELAYLOAD_DESCRIPTOR, * PIMAGE_DELAYLOAD_DESCRIPTOR;

enum E_DATA_DIR_TABLE
{
    E_EXPORT_TAB                    //导出表
    , E_IMPORT_TAB                  //导入表
    , E_RESOURCE_TAB                //资源表
    , E_EXCEPTION_TAB               //异常表
    , E_CERTIFICATE_TAB             //属性证书表
    , E_BASE_RELOCATION_TABLE       //基址重定位表
    , E_DEBUG_INFO_TABLE            //调试信息表
    , E_UNDEF_TABLE                 //预留表
    , E_GLOBAL_POINT_TABLE          //全局指针寄存器表
    , E_THREAD_LOCAL_TABLE          //线程局部存储表
    , E_LOAD_CONFIG_TABLE           //加载配置表
    , E_BOUND_IMPORT_TABLE          //绑定导入表
    , E_IMPORT_ADDRESS_TABLE        //导入函数地址表
    , E_DELAY_IMPORT_TABLE          //延迟导入表
    , E_CLR_RUNTIME_HEADER_TABLE    //CLR运行时头部数据表
    , E_RESERVED                    //系统保留
};

typedef class XXXPort_Fun_Name_Table
{
public:
    XXXPort_Fun_Name_Table()
    {}
    XXXPort_Fun_Name_Table(WORD index, XString& name, DWORD address)
        : m_index(index)
        , m_name(name)
        , m_address(address)
    {}
    virtual ~XXXPort_Fun_Name_Table()
    {}
    inline void set_index(WORD index) { m_index = index; };
    inline void set_name(const char* fun_name) { m_name = fun_name; }
    inline void set_address(DWORD address) { m_address = address; };

    inline WORD get_index() { return m_index; }
    inline XString get_name() { return m_name; }
    inline DWORD get_address() { return m_address; }

private:
    WORD m_index;
    XString m_name;
    DWORD m_address;
}XIMPORT_FUN_NAME_TABLE, * PXIMPORT_FUN_NAME_TABLE;
typedef XXXPort_Fun_Name_Table XEXPORT_FUN_NAME_TABLE, * PXEXPORT_FUN_NAME_TABLE;
typedef XXXPort_Fun_Name_Table XDELAY_IMPOR_FUN_NAME_TABLE, *PXDELAY_IMPOR_FUN_NAME_TABLE;
 
/************************************************************************************/
/*
**  导出表数据
**/
typedef std::list<XXXPort_Fun_Name_Table> XIMPORT_FUN_TABLE, * PXIMPORT_FUN_TABLE;
typedef XIMPORT_FUN_TABLE XEXPORT_FUN_TABLE, *PXEXPORT_FUN_TABLE;
typedef XIMPORT_FUN_TABLE XDELAY_IMPOR_FUN_TABLE, * PXDELAY_IMPOR_FUN_TABLE;
typedef struct tagExportData
{
    XString m_name;
    DWORD m_base;
    XEXPORT_FUN_TABLE m_fun_table;
}EXPORT_TABLE_DATA, * PEXPORT_TABLE_DATA;

/************************************************************************************
**  导入表数据
**/
typedef std::map<XString, XIMPORT_FUN_TABLE> XIMPOTR_TABLE_DATA, *PXIMPOTR_TABLE_DATA;
typedef XIMPOTR_TABLE_DATA XDELAY_IMPORTABLE, *PXDELAY_IMPORTABLE;

/************************************************************************************
**  重定位表数据
**/
typedef struct tagRelocationDataSub
{
    DWORD m_type;
    DWORD m_reloaction_offset;
}XRELOCATION_DATA_SUB, * PXRELOCATION_DATA_SUB;
 
typedef struct tagRelocationData
{
    XString m_section_name;
    std::list<XRELOCATION_DATA_SUB> m_sub_data;
}XRELOCATION_DATA, * PXRELOCATION_DATA;

/************************************************************************************
**  资源信息结构体
**/
typedef struct tagXResourceData
{
    XString m_name_dir1;
    XString m_name_dir2;
    DWORD m_page_code;

    struct  
    {
        DWORD m_rva;
        DWORD m_file_pos;
        DWORD m_size;
    }resourct_info;

}XRESOURCE_DATA, *PXRESOURCE_DATA;

/************************************************************************************
**  TLS信息
**/
typedef struct tagTLS
{
    IMAGE_TLS_DIRECTORY m_tls_dir;
    std::list<DWORD> m_tls_fun_callback;
}XTLS_DATA, *PXTLS_DATA;
 
class XFileHeadStream;
class XOptionHeadStream;
class XDataDirStream;
class XSectionTable;
class XSectionTableStream;
 
class XJyaoushingan
{
public:
    XJyaoushingan(); 
    virtual ~XJyaoushingan();

    /*
    **  设置本地文件路径
    **  param1：需要当中PE格式解析的文件路径
    */
    void set_file_path(const XString& file_path);
    /*
    **  设置内存模块基址
    **  param1：需要内存中解析PE的内存基址
    */
    void set_memory_buf(LPVOID buf_head);
    /*
    **  打开PE解析器。
    **  如果是文件PE那么会使用内存映射文件方式解析
    **  如果是内存PE那么会直接搜索内存
    **  如果发生多次open那么会把上一次的数据给清理掉
    **  返回值：如果打开成功返回true，否则返回false
    */
    bool open(); 
    /*
    **  关闭当前PE解析
    **  如果是文件PE那么会释放掉文件内存映射的内存
    **  如果是内存PE那么直接将buf指针为NULL，不会做内存释放
    */
    void close(); 
    /*
    **  得到错误编码
    **  如果XJyaoushingan方法返回值为false，那么你可以用这个
    **  得到内置的编码，通过查询编码你可以大概的知道为什么出错
    */
    DWORD get_last_err();
    /*
    **  判断是否存在MZ头。
    **  返回值：如果当前PE解析存在MZ头返回true，否则返回FALSE
    */
    bool is_mz();
    /*
    **  获取MZ头结构体信息
    **  param1：返回IMAGE_DOS_HEADER结构体信息给你
    **  返回值：如果获取成功返回true，否则返回false。
    **  备注：
    **      如果检测到不是MZ也会返回false具体是哪种错误需要调用get_last_err()来确定。
    **      请自行确保传出参数的内存正确，里面不会检测传出内存是否可写。
    */
    bool get_mz(IMAGE_DOS_HEADER& mz); 
    /*
    **  （如果有需要）修改MZ头结构体信息
    **  param1：需要修改的IMAGE_DOS_HEADER结构体信息
    **  返回值：如果获取成功返回true，否则返回false。
    **  备注：
    **      如果检测到不是MZ也会返回false具体是哪种错误需要调用get_last_err()来确定。
    **      请自行确保传入参数的内存正确，里面不会检测内存是否可读。
    */
    bool set_mz(IMAGE_DOS_HEADER& mz);
    /*
    **  得到PE节的偏移地址 
    **  返回值：如果获取成功返回PE节偏移，否则返回0。
    */
    DWORD get_pe_offset();

    /*
    **  判断是否存在PE头。
    **  返回值：如果当前PE解析存在PE头返回true，否则返回false
    **  备注：
    **      如果检测到不是MZ也会返回false具体是哪种错误需要调用get_last_err()来确定。
    */
    bool is_pe(); 
    /*
    **  获取文件头结构体信息
    **  param1：返回IMAGE_FILE_HEADER结构体信息给你
    **  返回值：如果获取成功返回true，否则返回false。
    **  备注：
    **      如果检测到不是PE也会返回false具体是哪种错误需要调用get_last_err()来确定。
    **      请自行确保传出参数的内存正确，里面不会检测传出内存是否可写。
    */
    bool get_file_head(IMAGE_FILE_HEADER& file_head); 
    /*
    **  （如果有需要）修改文件头结构体信息
    **  param1：需要修改的结构体信息
    **  返回值：如果修改成功返回true，否则返回false。
    **  备注：
    **      如果检测到不是PE也会返回false具体是哪种错误需要调用get_last_err()来确定。
    **      请自行确保传入参数的内存正确，里面不会检测内存是否可读。
    */
    bool set_file_head(IMAGE_FILE_HEADER& file_head);  

    /*
    **  获取选择头结构体信息
    **  param1：返回IMAGE_OPTIONAL_HEADER结构体信息给你
    **  返回值：如果获取成功返回true，否则返回false。
    **  备注：
    **      如果检测到不是PE也会返回false具体是哪种错误需要调用get_last_err()来确定。
    **      请自行确保传出参数的内存正确，里面不会检测传出内存是否可写。
    */
    bool get_option_head(IMAGE_OPTIONAL_HEADER& option_head); 
    /*
    **  （如果有需要）修改选择头结构体信息
    **  param1：需要修改的结构体信息
    **  返回值：如果修改成功返回true，否则返回false。
    **  备注：
    **      如果检测到不是PE也会返回false具体是哪种错误需要调用get_last_err()来确定。
    **      请自行确保传入参数的内存正确，里面不会检测内存是否可读。
    */
    bool set_option_head(IMAGE_OPTIONAL_HEADER& option_head); 

    /*
    **  获取指定的数据目录结构信息，
    **  param1：输入参数，指定你需要第几项数据目录，E_DATA_DIR_TABLE
    **  param2：输出参数，返回你指定的数据目录结果
    **  返回值：如果获取成功返回true，否则返回false。
    **  备注：
    **      如果检测到不是PE也会返回false具体是哪种错误需要调用get_last_err()来确定。
    **      请自行确保传出参数的内存正确，里面不会检测传出内存是否可写。
    */
    bool get_data_dir(E_DATA_DIR_TABLE dd, IMAGE_DATA_DIRECTORY& data_dir); 
    /*
    **  获取指定的数据目录结构信息，
    **  param1：得到所有的数据目录信息，而非单一查表
    **  返回值：如果获取成功返回true，否则返回false。
    **  备注：
    **      如果检测到不是PE也会返回false具体是哪种错误需要调用get_last_err()来确定。
    */
    bool get_data_dir(std::map<E_DATA_DIR_TABLE, IMAGE_DATA_DIRECTORY>& data_dir);
    /*
    **  （如果有需要）修改数据目录结构体信息
    **  param1：输入参数，指定你需要修改第几项数据目录，E_DATA_DIR_TABLE
    **  param2：输入参数，需要修改的结构体信息
    **  返回值：如果修改成功返回true，否则返回false。
    **  备注：
    **      如果检测到不是PE也会返回false具体是哪种错误需要调用get_last_err()来确定。
    **      请自行确保传入参数的内存正确，里面不会检测内存是否可读。
    */
    bool set_data_dir(E_DATA_DIR_TABLE dd, IMAGE_DATA_DIRECTORY& data_dir);

    /*
    **  判断是否存在节表。
    **  返回值：如果当前节解析存在PE头返回true，否则返回false
    **  备注：
    **      如果检测到不是节也会返回false具体是哪种错误需要调用get_last_err()来确定。
    */
    bool is_section();  
    /*
    **  得到当前节的数量。
    **  返回值：返回当前PE中一共有多少个节的数量
    **  备注：
    **      如果检测到不是节也会返回false具体是哪种错误需要调用get_last_err()来确定。
    */
    DWORD get_section_count();
    /*
    **  获取指定索引的节信息，
    **  param1：输入参数，指定你需要第几个节数据
    **  param2：输出参数，返回你指定的节数据
    **  返回值：如果获取成功返回true，否则返回false。
    **  备注：
    **      如果检测到不是PE也会返回false具体是哪种错误需要调用get_last_err()来确定。
    **      请自行确保传出参数的内存正确，里面不会检测传出内存是否可写。
    */
    bool get_section(DWORD index, IMAGE_SECTION_HEADER& section);
    /*
    **  获取所有节信息，
    **  param1：输入参数，所有节信息以list存储
    **  返回值：如果获取成功返回true，否则返回false。
    **  备注：
    **      如果检测到不是节也会返回false具体是哪种错误需要调用get_last_err()来确定。
    */
    bool get_section(std::list<IMAGE_SECTION_HEADER>& section); 
    /*
    **  （如果有需要）修改指定节信息
    **  param1：输入参数，指定你需要修改第几项节数据
    **  param2：输入参数，需要修改的结构体信息
    **  返回值：如果修改成功返回true，否则返回false。
    **  备注：
    **      如果检测到不是节也会返回false具体是哪种错误需要调用get_last_err()来确定。
    **      请自行确保传入参数的内存正确，里面不会检测内存是否可读。
    */
    bool set_section(DWORD index, IMAGE_SECTION_HEADER& section);
    /*
    **  虚拟（内存）地址转文件偏移，
    **  param1：输入参数，需要获取的虚拟地址
    **  param2：输出参数，如果你需要顺带节信息那么传递一个可写入的指针地址
    **  返回值：如果查询成功则返回对于的文件地址，如果查询失败返回0.
    **          内存PE永远返回的是它本身的地址
    **  备注：
    **      如果检测到不是PE也会返回false具体是哪种错误需要调用get_last_err()来确定。
    **      请自行确保传出参数的内存正确，里面不会检测传出内存是否可写。
    */
    DWORD rva_mem2file(DWORD address, PIMAGE_SECTION_HEADER section_head = NULL);

    /*
    **  获取输入表信息 
    **  param1：输出参数，返回当前PE的所有输入表数据内容
    **  返回值：如果获取成功返回true，否则返回false。
    **  备注：
    **      如果检测到不是PE也会返回false具体是哪种错误需要调用get_last_err()来确定。
    **      请自行确保传出参数的内存正确，里面不会检测传出内存是否可写。
    */
    bool get_importable(XIMPOTR_TABLE_DATA& import_data);
    /*
    **  获取输出表信息
    **  param1：输出参数，返回当前PE的所有输出表数据内容
    **  返回值：如果获取成功返回true，否则返回false。
    **  备注：
    **      如果检测到不是PE也会返回false具体是哪种错误需要调用get_last_err()来确定。
    **      请自行确保传出参数的内存正确，里面不会检测传出内存是否可写。
    */
    bool get_exportable(EXPORT_TABLE_DATA& exportable); 
    /*
    **  获取重定位表信息
    **  param1：输出参数，返回当前PE的所有重定位表数据内容
    **  返回值：如果获取成功返回true，否则返回false。
    **  备注：
    **      如果检测到不是PE也会返回false具体是哪种错误需要调用get_last_err()来确定。
    **      请自行确保传出参数的内存正确，里面不会检测传出内存是否可写。
    */
    bool get_relocation(std::list<XRELOCATION_DATA>& lrelocation); 
    /*
    **  获取资源表信息
    **  param1：输出参数，返回当前PE的所有资源表数据内容
    **  返回值：如果获取成功返回true，否则返回false。
    **  备注：
    **      如果检测到不是PE也会返回false具体是哪种错误需要调用get_last_err()来确定。
    **      请自行确保传出参数的内存正确，里面不会检测传出内存是否可写。
    */
    bool get_resource(std::list<XRESOURCE_DATA> data);
    /*
    **  获取延迟加载导入表
    **  param1：输出参数，返回当前PE的所有资源表数据内容
    **  返回值：如果获取成功返回true，否则返回false。
    **  备注：
    **      如果检测到不是PE也会返回false具体是哪种错误需要调用get_last_err()来确定。
    **      请自行确保传出参数的内存正确，里面不会检测传出内存是否可写。
    */
    bool get_delay_load_importable(XDELAY_IMPORTABLE& delay_importable);
    /*
    **  获取线程局部存储表
    **  param1：输出参数，返回当前PE的所有资源表数据内容
    **  返回值：如果获取成功返回true，否则返回false。
    **  备注：
    **      如果检测到不是PE也会返回false具体是哪种错误需要调用get_last_err()来确定。
    **      请自行确保传出参数的内存正确，里面不会检测传出内存是否可写。
    */
    bool get_thread_local_storage(XTLS_DATA& tls_data);

private:
    bool get_import_name_table(DWORD bridge, XIMPORT_FUN_TABLE& fun_table); 
private:
    //文件PE的存储路径
    XString m_file_path; 
    //文件句柄
    HANDLE m_fp_handle;
    //内存映射句柄
    HANDLE m_fp_map;

    union 
    { 
        LPVOID m_fp_bufer;
        LPVOID m_memory_buf;
    }; 

    //函数执行错误编码
    DWORD m_err;

    //mz头偏移指针
    PIMAGE_DOS_HEADER m_mz;
    bool m_bis_mz;

    //pe头偏移指针
    PIMAGE_NT_HEADERS m_pe;
    bool m_bis_pe;

    //节表偏移指针
    PIMAGE_SECTION_HEADER m_section;
    bool m_bis_section;
    //节表数量
    DWORD m_section_count;
};

/*
**  MZ头显示流
*/ 
class XMZStream
{
public:  
    XMZStream(const IMAGE_DOS_HEADER& dos);
    virtual ~XMZStream();

    bool init(const IMAGE_DOS_HEADER& dos); 
    XString to_string();

private:
    const IMAGE_DOS_HEADER* m_mz;
};

/*
**  PE头显示流
*/  
class XFileHeadStream
{
public:
    XFileHeadStream(const IMAGE_FILE_HEADER& file_head);
    virtual ~XFileHeadStream();

    void init(const IMAGE_FILE_HEADER& file_head);

    XString to_string();
    XString Machine();
    XString NumberOfSections();
    XString TimeDateStamp();
    XString PointerToSymbolTable();
    XString NumberOfSymbols();
    XString SizeOfOptionalHeader();
    XString Characteristics();

private:
    const IMAGE_FILE_HEADER* m_file_head;
};


class XOptionHeadStream
{
public:
    XOptionHeadStream(const IMAGE_OPTIONAL_HEADER& option_head);
    virtual ~XOptionHeadStream();

    void init(const IMAGE_OPTIONAL_HEADER& option_head);
    XString to_string();
    XString Magic();
    XString MajorLinkerVersion();
    XString MinorLinkerVersion();
    XString SizeOfCode();
    XString SizeOfInitializedData();
    XString SizeOfUninitializedData();
    XString AddressOfEntryPoint();
    XString BaseOfCode();
    XString BaseOfData();
    XString ImageBase();
    XString SectionAlignment();
    XString FileAlignment();
    XString MajorOperatingSystemVersion();
    XString MinorOperatingSystemVersion();
    XString MajorImageVersion();
    XString MinorImageVersion();
    XString MajorSubsystemVersion();
    XString MinorSubsystemVersion();
    XString Win32VersionValue();
    XString SizeOfImage();
    XString SizeOfHeaders();
    XString CheckSum();
    XString Subsystem();
    XString DllCharacteristics();
    XString SizeOfStackReserve();
    XString SizeOfStackCommit();
    XString SizeOfHeapReserve();
    XString SizeOfHeapCommit();
    XString LoaderFlags();
    XString NumberOfRvaAndSizes();

private:
    const IMAGE_OPTIONAL_HEADER* m_option_head;
};
 
class XDataDirStream
{
public:
    XDataDirStream(const std::map<E_DATA_DIR_TABLE, IMAGE_DATA_DIRECTORY>& data_dir);
    virtual ~XDataDirStream();
    void init(const std::map<E_DATA_DIR_TABLE, IMAGE_DATA_DIRECTORY>& data_dir);

    XString to_string();
private:
    const std::map<E_DATA_DIR_TABLE, IMAGE_DATA_DIRECTORY>* m_data_dir;
};

/*
**  节表
*/  
class XSectionTableStream
{
public: 
    XSectionTableStream(const IMAGE_SECTION_HEADER& section_handle);
    ~XSectionTableStream();

    void init(const IMAGE_SECTION_HEADER& section_handle);

    XString to_string(IMAGE_SECTION_HEADER& section);
    XString Name();
    XString PhysicalAddress();
    XString VirtualSize();
    XString VirtualAddress();
    XString SizeOfRawData();
    XString PointerToRawData();
    XString PointerToRelocations();
    XString PointerToLinenumbers();
    XString NumberOfRelocations();
    XString NumberOfLinenumbers();
    XString Characteristics();

private:
    const IMAGE_SECTION_HEADER* m_section_handle;
};