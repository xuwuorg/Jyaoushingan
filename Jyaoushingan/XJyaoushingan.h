#pragma once
/************************************************************************************
**  Copyright 2018 ~ 2222 ����
**  blog: http://www.xuwu.org
**  mail: xuwuorg#163.com
**
**  �ļ�����XJyaoushingan.h
**  ���ܣ�Windows PE�ṹ������
**
**  ģ�飺 XJyaoushingan
**
**  XJyaoushingan�ࣺ������ļ������ڴ����PE�ṹ�ķ�����
**  ������
**      ���ļ�����PE��ʽ��Ҫ������ӿ�����Ŀ���ļ�·��
**      void set_file_path(const XString& file_path);
**      ���ڴ����PE��ʽ��Ҫʹ������ӿڸ�����Ҫ������ģ���ַ
**      void set_memory_buf(LPVOID buf_head);
**
**      ��ʼ����PE��ʽ
**      bool open();
**      �رյ�ǰ���õ�Ŀ�����PE
**      void close();
**      �ӿں�������falseʱ����ͨ������������ж�Ϊʲô����
**      DWORD get_last_err();
**
**      �õ�PE��MZͷ��Ϣ
**      bool get_mz(IMAGE_DOS_HEADER& mz);
**      �ж�����ļ�(�ڴ�)�Ƿ���MZ�ļ���ʽ
**      bool is_mz();
**      �޸�MZͷ�ļ���Ϣ
**      bool set_mz(IMAGE_DOS_HEADER& mz);
**      �õ�PEͷƫ�Ƶ�ַ
**      DWORD get_pe_offset();
**
**      �ж��Ƿ���PEͷ
**      bool is_pe();
**      �õ��ļ�ͷ�ṹ����Ϣ
**      bool get_file_head(IMAGE_FILE_HEADER& file_head);
**      �޸��ļ�ͷ��Ϣ
**      bool set_file_head(IMAGE_FILE_HEADER& file_head);
**
**      �õ�ѡ��ͷ��Ϣ
**      bool get_option_head(IMAGE_OPTIONAL_HEADER& option_head);
**      �޸�ѡ��ͷ��Ϣ
**      bool set_option_head(IMAGE_OPTIONAL_HEADER& option_head);
**
**      ��ȡָ��������Ŀ¼
**      bool get_data_dir(E_DATA_DIR_TABLE dd, IMAGE_DATA_DIRECTORY& data_dir);
**      �õ���������Ŀ¼
**      bool get_data_dir(std::map<E_DATA_DIR_TABLE, IMAGE_DATA_DIRECTORY>& data_dir);
**      �޸�����Ŀ¼��
**      bool set_data_dir(E_DATA_DIR_TABLE dd, IMAGE_DATA_DIRECTORY& data_dir);
**
**      �Ƿ��н�
**      bool is_section();
**      �õ�������
**      DWORD get_section_count();
**      ��ȡ��i����
**      bool get_section(DWORD index, IMAGE_SECTION_HEADER& section);
**      ��ȡ������
**      bool get_section(std::list<IMAGE_SECTION_HEADER>& section);
**      �޸�ָ����
**      bool set_section(DWORD index, IMAGE_SECTION_HEADER& section);
**      ���������ַת�ļ���ַ
**      DWORD rva_mem2file(DWORD address, PIMAGE_SECTION_HEADER section_head = NULL);
**
**      �õ��������Ϣ
**      bool get_importable(IMPOTR_TABLE_DATA& import_data);
**      �õ���������Ϣ
**      bool get_exportable(EXPORT_TABLE_DATA& exportable);
**      �õ��ض�λ����Ϣ
**      bool get_relocation(std::list<XRELOCATION_DATA>& lrelocation);
**      �õ���Դ��Ϣ
**      bool get_resource(std::list<XRESOURCE_DATA> data);
**
**
***********                                                                ***********
**  ģ�飺 XXXXStream
**  XXXXStream�ࣺ��Ҫ�����ڷ���UI��ʾ����װ�ġ�
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

//XP��WinNT.h��Ȼû�д��ṹ��
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
    E_EXPORT_TAB                    //������
    , E_IMPORT_TAB                  //�����
    , E_RESOURCE_TAB                //��Դ��
    , E_EXCEPTION_TAB               //�쳣��
    , E_CERTIFICATE_TAB             //����֤���
    , E_BASE_RELOCATION_TABLE       //��ַ�ض�λ��
    , E_DEBUG_INFO_TABLE            //������Ϣ��
    , E_UNDEF_TABLE                 //Ԥ����
    , E_GLOBAL_POINT_TABLE          //ȫ��ָ��Ĵ�����
    , E_THREAD_LOCAL_TABLE          //�ֲ߳̾��洢��
    , E_LOAD_CONFIG_TABLE           //�������ñ�
    , E_BOUND_IMPORT_TABLE          //�󶨵����
    , E_IMPORT_ADDRESS_TABLE        //���뺯����ַ��
    , E_DELAY_IMPORT_TABLE          //�ӳٵ����
    , E_CLR_RUNTIME_HEADER_TABLE    //CLR����ʱͷ�����ݱ�
    , E_RESERVED                    //ϵͳ����
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
**  ����������
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
**  ���������
**/
typedef std::map<XString, XIMPORT_FUN_TABLE> XIMPOTR_TABLE_DATA, *PXIMPOTR_TABLE_DATA;
typedef XIMPOTR_TABLE_DATA XDELAY_IMPORTABLE, *PXDELAY_IMPORTABLE;

/************************************************************************************
**  �ض�λ������
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
**  ��Դ��Ϣ�ṹ��
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
    **  ���ñ����ļ�·��
    **  param1����Ҫ����PE��ʽ�������ļ�·��
    */
    void set_file_path(const XString& file_path);
    /*
    **  �����ڴ�ģ���ַ
    **  param1����Ҫ�ڴ��н���PE���ڴ��ַ
    */
    void set_memory_buf(LPVOID buf_head);
    /*
    **  ��PE��������
    **  ������ļ�PE��ô��ʹ���ڴ�ӳ���ļ���ʽ����
    **  ������ڴ�PE��ô��ֱ�������ڴ�
    **  ����������open��ô�����һ�ε����ݸ������
    **  ����ֵ������򿪳ɹ�����true�����򷵻�false
    */
    bool open(); 
    /*
    **  �رյ�ǰPE����
    **  ������ļ�PE��ô���ͷŵ��ļ��ڴ�ӳ����ڴ�
    **  ������ڴ�PE��ôֱ�ӽ�bufָ��ΪNULL���������ڴ��ͷ�
    */
    void close(); 
    /*
    **  �õ��������
    **  ���XJyaoushingan��������ֵΪfalse����ô����������
    **  �õ����õı��룬ͨ����ѯ��������Դ�ŵ�֪��Ϊʲô����
    */
    DWORD get_last_err();
    /*
    **  �ж��Ƿ����MZͷ��
    **  ����ֵ�������ǰPE��������MZͷ����true�����򷵻�FALSE
    */
    bool is_mz();
    /*
    **  ��ȡMZͷ�ṹ����Ϣ
    **  param1������IMAGE_DOS_HEADER�ṹ����Ϣ����
    **  ����ֵ�������ȡ�ɹ�����true�����򷵻�false��
    **  ��ע��
    **      �����⵽����MZҲ�᷵��false���������ִ�����Ҫ����get_last_err()��ȷ����
    **      ������ȷ�������������ڴ���ȷ�����治���⴫���ڴ��Ƿ��д��
    */
    bool get_mz(IMAGE_DOS_HEADER& mz); 
    /*
    **  ���������Ҫ���޸�MZͷ�ṹ����Ϣ
    **  param1����Ҫ�޸ĵ�IMAGE_DOS_HEADER�ṹ����Ϣ
    **  ����ֵ�������ȡ�ɹ�����true�����򷵻�false��
    **  ��ע��
    **      �����⵽����MZҲ�᷵��false���������ִ�����Ҫ����get_last_err()��ȷ����
    **      ������ȷ������������ڴ���ȷ�����治�����ڴ��Ƿ�ɶ���
    */
    bool set_mz(IMAGE_DOS_HEADER& mz);
    /*
    **  �õ�PE�ڵ�ƫ�Ƶ�ַ 
    **  ����ֵ�������ȡ�ɹ�����PE��ƫ�ƣ����򷵻�0��
    */
    DWORD get_pe_offset();

    /*
    **  �ж��Ƿ����PEͷ��
    **  ����ֵ�������ǰPE��������PEͷ����true�����򷵻�false
    **  ��ע��
    **      �����⵽����MZҲ�᷵��false���������ִ�����Ҫ����get_last_err()��ȷ����
    */
    bool is_pe(); 
    /*
    **  ��ȡ�ļ�ͷ�ṹ����Ϣ
    **  param1������IMAGE_FILE_HEADER�ṹ����Ϣ����
    **  ����ֵ�������ȡ�ɹ�����true�����򷵻�false��
    **  ��ע��
    **      �����⵽����PEҲ�᷵��false���������ִ�����Ҫ����get_last_err()��ȷ����
    **      ������ȷ�������������ڴ���ȷ�����治���⴫���ڴ��Ƿ��д��
    */
    bool get_file_head(IMAGE_FILE_HEADER& file_head); 
    /*
    **  ���������Ҫ���޸��ļ�ͷ�ṹ����Ϣ
    **  param1����Ҫ�޸ĵĽṹ����Ϣ
    **  ����ֵ������޸ĳɹ�����true�����򷵻�false��
    **  ��ע��
    **      �����⵽����PEҲ�᷵��false���������ִ�����Ҫ����get_last_err()��ȷ����
    **      ������ȷ������������ڴ���ȷ�����治�����ڴ��Ƿ�ɶ���
    */
    bool set_file_head(IMAGE_FILE_HEADER& file_head);  

    /*
    **  ��ȡѡ��ͷ�ṹ����Ϣ
    **  param1������IMAGE_OPTIONAL_HEADER�ṹ����Ϣ����
    **  ����ֵ�������ȡ�ɹ�����true�����򷵻�false��
    **  ��ע��
    **      �����⵽����PEҲ�᷵��false���������ִ�����Ҫ����get_last_err()��ȷ����
    **      ������ȷ�������������ڴ���ȷ�����治���⴫���ڴ��Ƿ��д��
    */
    bool get_option_head(IMAGE_OPTIONAL_HEADER& option_head); 
    /*
    **  ���������Ҫ���޸�ѡ��ͷ�ṹ����Ϣ
    **  param1����Ҫ�޸ĵĽṹ����Ϣ
    **  ����ֵ������޸ĳɹ�����true�����򷵻�false��
    **  ��ע��
    **      �����⵽����PEҲ�᷵��false���������ִ�����Ҫ����get_last_err()��ȷ����
    **      ������ȷ������������ڴ���ȷ�����治�����ڴ��Ƿ�ɶ���
    */
    bool set_option_head(IMAGE_OPTIONAL_HEADER& option_head); 

    /*
    **  ��ȡָ��������Ŀ¼�ṹ��Ϣ��
    **  param1�����������ָ������Ҫ�ڼ�������Ŀ¼��E_DATA_DIR_TABLE
    **  param2�����������������ָ��������Ŀ¼���
    **  ����ֵ�������ȡ�ɹ�����true�����򷵻�false��
    **  ��ע��
    **      �����⵽����PEҲ�᷵��false���������ִ�����Ҫ����get_last_err()��ȷ����
    **      ������ȷ�������������ڴ���ȷ�����治���⴫���ڴ��Ƿ��д��
    */
    bool get_data_dir(E_DATA_DIR_TABLE dd, IMAGE_DATA_DIRECTORY& data_dir); 
    /*
    **  ��ȡָ��������Ŀ¼�ṹ��Ϣ��
    **  param1���õ����е�����Ŀ¼��Ϣ�����ǵ�һ���
    **  ����ֵ�������ȡ�ɹ�����true�����򷵻�false��
    **  ��ע��
    **      �����⵽����PEҲ�᷵��false���������ִ�����Ҫ����get_last_err()��ȷ����
    */
    bool get_data_dir(std::map<E_DATA_DIR_TABLE, IMAGE_DATA_DIRECTORY>& data_dir);
    /*
    **  ���������Ҫ���޸�����Ŀ¼�ṹ����Ϣ
    **  param1�����������ָ������Ҫ�޸ĵڼ�������Ŀ¼��E_DATA_DIR_TABLE
    **  param2�������������Ҫ�޸ĵĽṹ����Ϣ
    **  ����ֵ������޸ĳɹ�����true�����򷵻�false��
    **  ��ע��
    **      �����⵽����PEҲ�᷵��false���������ִ�����Ҫ����get_last_err()��ȷ����
    **      ������ȷ������������ڴ���ȷ�����治�����ڴ��Ƿ�ɶ���
    */
    bool set_data_dir(E_DATA_DIR_TABLE dd, IMAGE_DATA_DIRECTORY& data_dir);

    /*
    **  �ж��Ƿ���ڽڱ�
    **  ����ֵ�������ǰ�ڽ�������PEͷ����true�����򷵻�false
    **  ��ע��
    **      �����⵽���ǽ�Ҳ�᷵��false���������ִ�����Ҫ����get_last_err()��ȷ����
    */
    bool is_section();  
    /*
    **  �õ���ǰ�ڵ�������
    **  ����ֵ�����ص�ǰPE��һ���ж��ٸ��ڵ�����
    **  ��ע��
    **      �����⵽���ǽ�Ҳ�᷵��false���������ִ�����Ҫ����get_last_err()��ȷ����
    */
    DWORD get_section_count();
    /*
    **  ��ȡָ�������Ľ���Ϣ��
    **  param1�����������ָ������Ҫ�ڼ���������
    **  param2�����������������ָ���Ľ�����
    **  ����ֵ�������ȡ�ɹ�����true�����򷵻�false��
    **  ��ע��
    **      �����⵽����PEҲ�᷵��false���������ִ�����Ҫ����get_last_err()��ȷ����
    **      ������ȷ�������������ڴ���ȷ�����治���⴫���ڴ��Ƿ��д��
    */
    bool get_section(DWORD index, IMAGE_SECTION_HEADER& section);
    /*
    **  ��ȡ���н���Ϣ��
    **  param1��������������н���Ϣ��list�洢
    **  ����ֵ�������ȡ�ɹ�����true�����򷵻�false��
    **  ��ע��
    **      �����⵽���ǽ�Ҳ�᷵��false���������ִ�����Ҫ����get_last_err()��ȷ����
    */
    bool get_section(std::list<IMAGE_SECTION_HEADER>& section); 
    /*
    **  ���������Ҫ���޸�ָ������Ϣ
    **  param1�����������ָ������Ҫ�޸ĵڼ��������
    **  param2�������������Ҫ�޸ĵĽṹ����Ϣ
    **  ����ֵ������޸ĳɹ�����true�����򷵻�false��
    **  ��ע��
    **      �����⵽���ǽ�Ҳ�᷵��false���������ִ�����Ҫ����get_last_err()��ȷ����
    **      ������ȷ������������ڴ���ȷ�����治�����ڴ��Ƿ�ɶ���
    */
    bool set_section(DWORD index, IMAGE_SECTION_HEADER& section);
    /*
    **  ���⣨�ڴ棩��ַת�ļ�ƫ�ƣ�
    **  param1�������������Ҫ��ȡ�������ַ
    **  param2������������������Ҫ˳������Ϣ��ô����һ����д���ָ���ַ
    **  ����ֵ�������ѯ�ɹ��򷵻ض��ڵ��ļ���ַ�������ѯʧ�ܷ���0.
    **          �ڴ�PE��Զ���ص���������ĵ�ַ
    **  ��ע��
    **      �����⵽����PEҲ�᷵��false���������ִ�����Ҫ����get_last_err()��ȷ����
    **      ������ȷ�������������ڴ���ȷ�����治���⴫���ڴ��Ƿ��д��
    */
    DWORD rva_mem2file(DWORD address, PIMAGE_SECTION_HEADER section_head = NULL);

    /*
    **  ��ȡ�������Ϣ 
    **  param1��������������ص�ǰPE�������������������
    **  ����ֵ�������ȡ�ɹ�����true�����򷵻�false��
    **  ��ע��
    **      �����⵽����PEҲ�᷵��false���������ִ�����Ҫ����get_last_err()��ȷ����
    **      ������ȷ�������������ڴ���ȷ�����治���⴫���ڴ��Ƿ��д��
    */
    bool get_importable(XIMPOTR_TABLE_DATA& import_data);
    /*
    **  ��ȡ�������Ϣ
    **  param1��������������ص�ǰPE�������������������
    **  ����ֵ�������ȡ�ɹ�����true�����򷵻�false��
    **  ��ע��
    **      �����⵽����PEҲ�᷵��false���������ִ�����Ҫ����get_last_err()��ȷ����
    **      ������ȷ�������������ڴ���ȷ�����治���⴫���ڴ��Ƿ��д��
    */
    bool get_exportable(EXPORT_TABLE_DATA& exportable); 
    /*
    **  ��ȡ�ض�λ����Ϣ
    **  param1��������������ص�ǰPE�������ض�λ����������
    **  ����ֵ�������ȡ�ɹ�����true�����򷵻�false��
    **  ��ע��
    **      �����⵽����PEҲ�᷵��false���������ִ�����Ҫ����get_last_err()��ȷ����
    **      ������ȷ�������������ڴ���ȷ�����治���⴫���ڴ��Ƿ��д��
    */
    bool get_relocation(std::list<XRELOCATION_DATA>& lrelocation); 
    /*
    **  ��ȡ��Դ����Ϣ
    **  param1��������������ص�ǰPE��������Դ����������
    **  ����ֵ�������ȡ�ɹ�����true�����򷵻�false��
    **  ��ע��
    **      �����⵽����PEҲ�᷵��false���������ִ�����Ҫ����get_last_err()��ȷ����
    **      ������ȷ�������������ڴ���ȷ�����治���⴫���ڴ��Ƿ��д��
    */
    bool get_resource(std::list<XRESOURCE_DATA> data);
    /*
    **  ��ȡ�ӳټ��ص����
    **  param1��������������ص�ǰPE��������Դ����������
    **  ����ֵ�������ȡ�ɹ�����true�����򷵻�false��
    **  ��ע��
    **      �����⵽����PEҲ�᷵��false���������ִ�����Ҫ����get_last_err()��ȷ����
    **      ������ȷ�������������ڴ���ȷ�����治���⴫���ڴ��Ƿ��д��
    */
    bool get_delay_load_importable(XDELAY_IMPORTABLE& delay_importable);


private:
    bool get_import_name_table(DWORD bridge, XIMPORT_FUN_TABLE& fun_table); 
private:
    //�ļ�PE�Ĵ洢·��
    XString m_file_path; 
    //�ļ����
    HANDLE m_fp_handle;
    //�ڴ�ӳ����
    HANDLE m_fp_map;

    union 
    { 
        LPVOID m_fp_bufer;
        LPVOID m_memory_buf;
    }; 

    //����ִ�д������
    DWORD m_err;

    //mzͷƫ��ָ��
    PIMAGE_DOS_HEADER m_mz;
    bool m_bis_mz;

    //peͷƫ��ָ��
    PIMAGE_NT_HEADERS m_pe;
    bool m_bis_pe;

    //�ڱ�ƫ��ָ��
    PIMAGE_SECTION_HEADER m_section;
    bool m_bis_section;
    //�ڱ�����
    DWORD m_section_count;
};

/*
**  MZͷ��ʾ��
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
**  PEͷ��ʾ��
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
**  �ڱ�
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