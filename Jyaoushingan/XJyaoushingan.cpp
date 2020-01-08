#include "pch.h"
#include "XJyaoushingan.h"
#include <time.h>
     
#define IS_POINT_EMPTY_RET_WCSNULL(point)\
{if (point == NULL) return L"";}

#define NOT_INIT() \
if (m_fp_bufer == NULL || IsBadReadPtr(m_fp_bufer, sizeof(LPVOID)))\
{\
return false;\
}

#define GET_DATA_DIR_POINT(INDEX, OUT_DIR, OUT_POINT_TYPE, OUT_POINT)\
{\
if (!get_data_dir(INDEX, OUT_DIR))\
{\
break; \
}\
DWORD offset_name = rva_mem2file(OUT_DIR.VirtualAddress); \
if (offset_name == 0)\
{\
break; \
}\
OUT_POINT = (OUT_POINT_TYPE)GET_OFFSET_BUFFER(m_fp_bufer, offset_name); \
}

#define GET_OFFSET_BUFFER(p, o) (LPVOID)((DWORD)p + o) 
#define PE_SIGN 4


WCHAR g_resource_name[16][16] = { L"光标", L"位图", L"图标", L"菜单", L"对话框",
                                L"字符串", L"字体目录", L"字体", L"快捷键", L"未格式化资源",
                                L"消息表", L"光标组", L"", L"图标组", L"", L"版本" };

XJyaoushingan::XJyaoushingan()
    : m_file_path(L"")
    , m_fp_handle(INVALID_HANDLE_VALUE)
    , m_fp_map(INVALID_HANDLE_VALUE)
    , m_fp_bufer(NULL)
    , m_err(0)
    , m_mz(NULL)
    , m_bis_mz(false)
    , m_pe(NULL)
    , m_bis_pe(false)
    , m_section(NULL)
    , m_bis_section(false)
    , m_section_count(0)

{
}

XJyaoushingan::~XJyaoushingan()
{
    close();
}

DWORD 
XJyaoushingan::get_last_err()
{
    return m_err;
}

void 
XJyaoushingan::close()
{
    if (m_fp_bufer != NULL)
    {
        if (m_fp_map != INVALID_HANDLE_VALUE)
        {
            ::UnmapViewOfFile(m_fp_bufer);
        } 
        m_fp_bufer = NULL;
    }

    if (m_fp_map != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(m_fp_map);
        m_fp_map = INVALID_HANDLE_VALUE;
    }

    if (m_fp_handle != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(m_fp_handle);
        m_fp_handle = INVALID_HANDLE_VALUE;
    }

    m_mz = NULL;
    m_bis_mz = false;

    m_pe = NULL;
    m_bis_pe = false;

    m_section = NULL;
    m_bis_section = false;
    m_section_count = 0;
}

void 
XJyaoushingan::set_file_path(
    const XString & file_path)
{
    m_file_path = file_path;
}

void 
XJyaoushingan::set_memory_buf(
    LPVOID buf_head)
{
    m_memory_buf = buf_head;
}

bool 
XJyaoushingan::open()
{
    if (m_memory_buf != NULL 
        && !IsBadReadPtr(m_memory_buf, sizeof(PVOID)))
    {
        return true;
    }

    if (m_fp_handle != INVALID_HANDLE_VALUE)
    {
        close();
    }

    do
    {
        m_fp_handle = ::CreateFile(
            m_file_path.w_cstr()
            , GENERIC_READ | GENERIC_WRITE
            , 0
            , NULL
            , OPEN_ALWAYS
            , FILE_ATTRIBUTE_NORMAL
            , NULL);
        if (m_fp_handle == INVALID_HANDLE_VALUE)
        {
            break;
        }

        DWORD heigh = 0;
        DWORD low = 0;
        low = ::GetFileSize(m_fp_handle, &heigh);

        m_fp_map = ::CreateFileMapping(m_fp_handle,
            NULL,
            PAGE_READWRITE,
            heigh,
            low,
            NULL);
        if (m_fp_map == NULL)
        {
            break;
        }

        m_fp_bufer = ::MapViewOfFile(
            m_fp_map
            , FILE_MAP_READ | FILE_MAP_WRITE
            , 0
            , 0
            , low);
        if (m_fp_bufer == NULL)
        {
            break;
        }

        return true;
    } while (false);

    m_err = ::GetLastError();

    close();
    return false;
}

bool 
XJyaoushingan::get_mz(
    IMAGE_DOS_HEADER& mz)
 {
    if (is_mz())
    {
        memcpy(&mz, m_mz, sizeof(IMAGE_DOS_HEADER));
        return true;
    }
     
    return false;  
}

bool
XJyaoushingan::is_mz()
{
    NOT_INIT();

    if (m_bis_mz)
    {
        return m_bis_mz;
    }

    m_mz = (PIMAGE_DOS_HEADER)m_fp_bufer;
    if (m_mz->e_magic != 0x5A4D)
    {
        m_mz = NULL;
        return false;
    }

    m_bis_mz = true;
    return true;
}

DWORD 
XJyaoushingan::get_pe_offset()
{
    if (is_mz())
    {
        return m_mz->e_lfanew;
    }

    return 0;
} 

bool 
XJyaoushingan::set_mz(
    IMAGE_DOS_HEADER & mz)
{
    if (is_mz())
    {
        memcpy(m_mz, &mz, sizeof(IMAGE_DOS_HEADER));
        return true;
    }

    return false; 
}
  
bool 
XJyaoushingan::is_pe()
{
    NOT_INIT();

    if (m_bis_pe)
    {
        return m_bis_pe;
    }

    ULONG offset = get_pe_offset();
    if (offset == 0)
    {
        return false;
    }

    m_pe = (PIMAGE_NT_HEADERS)GET_OFFSET_BUFFER(m_fp_bufer, offset);
    if (m_pe->Signature != 0x4550)
    {
        m_pe = NULL;
        m_bis_pe = false;
    }

    m_bis_pe = true;
    return m_bis_pe;
}

bool 
XJyaoushingan::get_file_head(
    IMAGE_FILE_HEADER & file_head)
{ 
    if (!is_pe())
    {
        return false;
    }

    memcpy(&file_head, &m_pe->FileHeader, sizeof(IMAGE_FILE_HEADER));
    return true;
}

bool 
XJyaoushingan::set_file_head(
    IMAGE_FILE_HEADER & file_head)
{
    if (!is_pe())
    {
        return false;
    }

    memcpy(&m_pe->FileHeader, &file_head, sizeof(IMAGE_FILE_HEADER));
    return true;
}

bool 
XJyaoushingan::get_option_head(
    IMAGE_OPTIONAL_HEADER & option_head)
{
    if (!is_pe())
    {
        return false;
    }

    memcpy(&option_head, &m_pe->OptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER));
    return true;
}

bool 
XJyaoushingan::set_option_head(
    IMAGE_OPTIONAL_HEADER & option_head)
{
    if (!is_pe())
    {
        return false;
    }

    memcpy(&m_pe->OptionalHeader, &option_head, sizeof(IMAGE_OPTIONAL_HEADER));
    return true;
}

bool 
XJyaoushingan::get_data_dir(
    E_DATA_DIR_TABLE dd
    , IMAGE_DATA_DIRECTORY& data_dir)
{
    if (!is_pe())
    {
        return false;
    }

    if (dd < E_EXPORT_TAB || dd > E_RESERVED)
    {
        return false;
    }

    memcpy(&data_dir, &m_pe->OptionalHeader.DataDirectory[dd], sizeof(IMAGE_DATA_DIRECTORY));
    return true;
}

bool 
XJyaoushingan::get_data_dir(
    std::map<E_DATA_DIR_TABLE, IMAGE_DATA_DIRECTORY>& data_dir)
{
    if (!is_pe())
    {
        return false;
    }

    for (int i = 0; i <= E_RESERVED; i++)
    {
        IMAGE_DATA_DIRECTORY dd;
        memcpy(&dd, &m_pe->OptionalHeader.DataDirectory[i], sizeof(IMAGE_DATA_DIRECTORY));
        data_dir.insert(std::pair<E_DATA_DIR_TABLE, IMAGE_DATA_DIRECTORY>((E_DATA_DIR_TABLE)i, dd));
    }

    return true;
}

bool 
XJyaoushingan::set_data_dir(
    E_DATA_DIR_TABLE dd
    , IMAGE_DATA_DIRECTORY & data_dir)
{
    if (!is_pe())
    {
        return false;
    }

    if (dd < E_EXPORT_TAB || dd > E_RESERVED)
    {
        return false;
    }

    memcpy(&m_pe->OptionalHeader.DataDirectory[dd], &data_dir, sizeof(IMAGE_DATA_DIRECTORY));
    return true;
}

bool 
XJyaoushingan::is_section()
{
    NOT_INIT();

    if (m_bis_section)
    {
        return m_bis_section;
    }

    IMAGE_FILE_HEADER file_head;
    if (!get_file_head(file_head))
    {
        return false;
    }
      
    DWORD section_offset = get_pe_offset()
        + PE_SIGN
        + sizeof(IMAGE_FILE_HEADER)
        + file_head.SizeOfOptionalHeader;

    m_section 
        = (PIMAGE_SECTION_HEADER)GET_OFFSET_BUFFER(m_fp_bufer, section_offset);
    m_section_count = file_head.NumberOfSections;
    return true;
}

DWORD
XJyaoushingan::get_section_count()
{
    return m_section_count;
}

bool 
XJyaoushingan::get_section(
    DWORD index
    , IMAGE_SECTION_HEADER& section)
{
    if (index > get_section_count())
    {
        return false;
    }

    memcpy(&section, &m_section[index], sizeof(IMAGE_SECTION_HEADER));
    return true;
}

bool 
XJyaoushingan::get_section(
    std::list<IMAGE_SECTION_HEADER>& section)
{
    if (!is_section())
    {
        return false;
    }

    for (DWORD i = 0; i < get_section_count(); i++)
    {
        IMAGE_SECTION_HEADER sh;
        if (get_section(i, sh))
        {
            section.push_back(sh);
        }
    }

    return true;
}

bool 
XJyaoushingan::set_section(
    DWORD index
    , IMAGE_SECTION_HEADER& section)
{
    if (!is_section())
    {
        return false;
    }

    if (index > get_section_count())
    {
        return false;
    }

    memcpy(&m_section[index], &section, sizeof(IMAGE_SECTION_HEADER));
    return true;
}

DWORD 
XJyaoushingan::rva_mem2file(
    DWORD address
    , PIMAGE_SECTION_HEADER section_head)
{ 
    do
    { 
        if (!is_section())
        {
            break;
        }

        std::list<IMAGE_SECTION_HEADER> vt;
        if (!get_section(vt))
        {
            break;
        }

        std::list<IMAGE_SECTION_HEADER>::iterator it = vt.begin();
        for (it; it != vt.end(); it++)
        {
            DWORD section_size = it->VirtualAddress + it->SizeOfRawData;
            if ((it->VirtualAddress <= address) && (address <= section_size))
            {
                if (section_head != NULL)
                {
                    memcpy(section_head, (LPVOID) & (*it), sizeof(IMAGE_SECTION_HEADER));
                }
                 
                if (m_fp_map == INVALID_HANDLE_VALUE)
                {
                    return address;
                }
                else
                {
                    DWORD pos = address - it->VirtualAddress + it->PointerToRawData;
                    return pos;
                }
            }
        }

    } while (false);

    return 0;
}

bool 
XJyaoushingan::get_importable(
    XIMPOTR_TABLE_DATA& import_data)
{
    import_data.clear();

    do
    { 
        IMAGE_DATA_DIRECTORY import_name;
        PIMAGE_IMPORT_DESCRIPTOR import_descriptor;
        GET_DATA_DIR_POINT(
            E_IMPORT_TAB
            , import_name
            , PIMAGE_IMPORT_DESCRIPTOR
            , import_descriptor);
//         IMAGE_DATA_DIRECTORY import_name;
//         if (!get_data_dir(E_IMPORT_TAB, import_name))
//         {
//             break;
//         }
// 
//         //         IMAGE_DATA_DIRECTORY import_fun;
//         //         if (!get_data_dir(E_IMPORT_ADDRESS_TABLE, import_fun))
//         //         {
//         //             break;
//         //         }
// 
//         DWORD offset_name = rva_mem2file(import_name.VirtualAddress);
//         if (offset_name == 0)
//         {
//             break;
//         }
// 
//         //         DWORD offset_fun = rva_mem2file(import_fun.VirtualAddress);
//         //         if (offset_fun == 0)
//         //         {
//         //             break;
//         //         }
// 
//         PIMAGE_IMPORT_DESCRIPTOR import_descriptor 
//             = (PIMAGE_IMPORT_DESCRIPTOR)GET_OFFSET_BUFFER(m_fp_bufer, offset_name);
//         /*        DWORD pos2 = (DWORD)GET_OFFSET_BUFFER(m_fp_bufer, offset_fun);*/

        for (DWORD pos = 0;
            pos < import_name.Size;
            pos += sizeof(IMAGE_IMPORT_DESCRIPTOR), import_descriptor++)
        {
            DWORD name_pos = rva_mem2file(import_descriptor->Name);
            char* name = (char*)GET_OFFSET_BUFFER(m_fp_bufer, name_pos);
            XString dll_name(name);

            XIMPORT_FUN_TABLE fun_table;

            DWORD bridge1 = rva_mem2file(import_descriptor->OriginalFirstThunk);
            DWORD bridge2 = rva_mem2file(import_descriptor->FirstThunk);
            if (bridge1 != 0)
            {
                get_import_name_table(bridge1, fun_table);
            }
            else if (bridge2 != 0)
            {
                get_import_name_table(bridge2, fun_table);
            }
            else
                break;

            import_data.insert(std::pair<XString, XIMPORT_FUN_TABLE>(dll_name, fun_table));
        }

        return true;
    } while (false);

    return false;
}

bool 
XJyaoushingan::get_import_name_table(
    DWORD bridge
    , XIMPORT_FUN_TABLE& fun_table)
{
    DWORD* import_name_table = (DWORD*)GET_OFFSET_BUFFER(m_fp_bufer, bridge);
    for (; *import_name_table != 0; import_name_table++)
    {
        DWORD fa = rva_mem2file(*import_name_table);
        PIMAGE_IMPORT_BY_NAME import_name = (PIMAGE_IMPORT_BY_NAME)GET_OFFSET_BUFFER(m_fp_bufer, fa);

        XIMPORT_FUN_NAME_TABLE table;
        table.set_address(0);
        table.set_index(import_name->Hint);
        table.set_name((const char*)import_name->Name);

        fun_table.push_back(table);
    }

    return true;
}

bool 
XJyaoushingan::get_exportable(
    EXPORT_TABLE_DATA & expdata)
{
    do
    {
        IMAGE_DATA_DIRECTORY exportable;
        PIMAGE_EXPORT_DIRECTORY export_descriptor;
        GET_DATA_DIR_POINT(
            E_EXPORT_TAB
            , exportable
            , PIMAGE_EXPORT_DIRECTORY
            , export_descriptor);
          
        DWORD name_pos = rva_mem2file(export_descriptor->Name);
        char* name = (char*)GET_OFFSET_BUFFER(m_fp_bufer, name_pos);
        XString dll_name(name);

        DWORD offset = rva_mem2file(export_descriptor->AddressOfNameOrdinals);
        WORD* AddressOfNameOrdinals = (WORD*)GET_OFFSET_BUFFER(m_fp_bufer, offset);

        offset = rva_mem2file(export_descriptor->AddressOfNames);
        DWORD* AddressOfNames = (DWORD*)GET_OFFSET_BUFFER(m_fp_bufer, offset);

        offset = rva_mem2file(export_descriptor->AddressOfFunctions);
        DWORD* AddressOfFunctions = (DWORD*)GET_OFFSET_BUFFER(m_fp_bufer, offset);

        IMAGE_OPTIONAL_HEADER option;
        if (!get_option_head(option))
        {
            break;
        }

        expdata.m_name = dll_name;
        expdata.m_base = option.ImageBase;

        for (DWORD i = 0; i < export_descriptor->NumberOfNames; i++)
        {
            WORD index = *AddressOfNameOrdinals;

            offset = rva_mem2file(*AddressOfNames);
            const char* exp_name = (const char*)GET_OFFSET_BUFFER(m_fp_bufer, offset);
            XString xname(exp_name);

            DWORD fun_address = option.ImageBase + *AddressOfFunctions;

            XEXPORT_FUN_NAME_TABLE data(index, xname, fun_address);
            expdata.m_fun_table.push_back(data);

            AddressOfNameOrdinals++;
            AddressOfNames++;
            AddressOfFunctions++;
        }

        return true;
    } while (false);

    return false;
}

bool 
XJyaoushingan::get_relocation(
    std::list<XRELOCATION_DATA> & lrelocation)
{
    do
    { 
        IMAGE_DATA_DIRECTORY relocation;
        if (!get_data_dir(E_BASE_RELOCATION_TABLE, relocation))
        {
            break;
        }

        DWORD offset = rva_mem2file(relocation.VirtualAddress);
        if (offset == 0)
        {
            break;
        }
         
        DWORD count = 0;
        for (DWORD index = 0; index < relocation.Size; index += count)
        { 
            PIMAGE_BASE_RELOCATION relocation_descriptor
                = (PIMAGE_BASE_RELOCATION)GET_OFFSET_BUFFER(m_fp_bufer, offset);
            if (relocation_descriptor == NULL)
            {
                break;
            }

            IMAGE_SECTION_HEADER section;
            DWORD pos = rva_mem2file(relocation_descriptor->VirtualAddress, &section);
            if (pos != 0)
            {
                XRELOCATION_DATA data;
                data.m_section_name = (char*)section.Name;

                WORD* pblock = (WORD*)((DWORD)relocation_descriptor + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD block_index = 0
                    ; block_index < (relocation_descriptor->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2
                    ; block_index++)
                {
                    WORD block = pblock[block_index];

                    XRELOCATION_DATA_SUB subdata;
                    subdata.m_type = (block & 0xF000) / 0x1000;
                    subdata.m_reloaction_offset = (block & 0x0FFF);

                    data.m_sub_data.push_back(subdata);
                }

                lrelocation.push_back(data);
            }

            count = relocation_descriptor->SizeOfBlock;
            offset += relocation_descriptor->SizeOfBlock;
        }

        return true;
    } while (false);

    return false;
}

bool 
XJyaoushingan::get_resource(
    std::list<XRESOURCE_DATA> list_data)
{
    do
    {
        IMAGE_DATA_DIRECTORY recource;
        PIMAGE_RESOURCE_DIRECTORY rd_root;
        GET_DATA_DIR_POINT(
            E_RESOURCE_TAB
            , recource
            , PIMAGE_RESOURCE_DIRECTORY
            , rd_root);
          
        DWORD rs = rd_root->NumberOfIdEntries + rd_root->NumberOfNamedEntries;

        PIMAGE_RESOURCE_DIRECTORY_ENTRY rde =
            (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)rd_root + sizeof(IMAGE_RESOURCE_DIRECTORY));

        for (DWORD index = 0; index < rs; index++, rde++)
        {
            XRESOURCE_DATA data;

            XString name1;
            if (rde->NameIsString == 1)
            {
                PIMAGE_RESOURCE_DIR_STRING_U resource_dir_string =
                    (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)rd_root + rde->NameOffset);

                data.m_name_dir1 = resource_dir_string->NameString;
            }
            else
            {
                if (rde->Name > 0 && rde->Name <= 0x10)
                { 
                    data.m_name_dir1 = g_resource_name[rde->Name];
                }
                else
                {
                    data.m_name_dir1 = rde->Name;
                } 
            }

            PIMAGE_RESOURCE_DIRECTORY rd2
                = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)rd_root + rde->OffsetToDirectory);

            DWORD rs2 = rd2->NumberOfIdEntries + rd2->NumberOfNamedEntries;

            PIMAGE_RESOURCE_DIRECTORY_ENTRY rde2 =
                (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)rd2 + sizeof(IMAGE_RESOURCE_DIRECTORY));

            for (DWORD index2 = 0; index2 < rs2; index2++, rde2++)
            {
                if (rde2->DataIsDirectory != 1)
                {
                     continue;
                } 
                  
                //输出第二层资源的标识看是数字还是字符串
                if (rde2->NameIsString == 1)
                {
                    PIMAGE_RESOURCE_DIR_STRING_U resource_dir_string =
                        (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)rd_root + rde2->NameOffset);

                    data.m_name_dir2 = resource_dir_string->NameString;
                }
                else
                { 
                    data.m_name_dir2 = rde2->Id;
                }

                //解析第三层 
                PIMAGE_RESOURCE_DIRECTORY pResD3
                    = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)rd_root + rde2->OffsetToDirectory);

                PIMAGE_RESOURCE_DIRECTORY_ENTRY pResDE3
                    = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((long)pResD3 + sizeof(IMAGE_RESOURCE_DIRECTORY));

                PIMAGE_RESOURCE_DATA_ENTRY pResDataE
                    = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)rd_root + pResDE3->OffsetToData);

                data.m_page_code = pResDE3->Id;

                data.resourct_info.m_rva = pResDataE->OffsetToData;
                data.resourct_info.m_file_pos = rva_mem2file(pResDataE->OffsetToData);
                data.resourct_info.m_size = pResDataE->Size;

                list_data.push_back(data);
            } 
        }

        return true;
    } while (false);

    return false;
}

bool 
XJyaoushingan::get_delay_load_importable(
    XDELAY_IMPORTABLE& delay_importable)
{
    do
    {
        IMAGE_DATA_DIRECTORY delay_load_importable;
        PIMAGE_DELAYLOAD_DESCRIPTOR pdd;
        GET_DATA_DIR_POINT(
            E_DELAY_IMPORT_TABLE
            , delay_load_importable
            , PIMAGE_DELAYLOAD_DESCRIPTOR
            , pdd); 

        DWORD count = delay_load_importable.Size / sizeof(IMAGE_DELAYLOAD_DESCRIPTOR);
        for (DWORD i = 0; i < count; i++, pdd++)
        {
            DWORD offset = rva_mem2file(pdd->DllNameRVA);
            char* pszdllname = (char*)GET_OFFSET_BUFFER(m_fp_bufer, offset);

            XString dllname(pszdllname);

            DWORD bridge1 = rva_mem2file(pdd->ImportNameTableRVA);
            DWORD bridge2 = rva_mem2file(pdd->ImportNameTableRVA);

            XIMPORT_FUN_TABLE fun_table;
            if (bridge1 != 0)
            {
                get_import_name_table(bridge1, fun_table);
            }
            else if (bridge2 != 0)
            {
                get_import_name_table(bridge2, fun_table);
            }

            if (!fun_table.empty())
            { 
                delay_importable.insert(
                    std::pair<XString, XDELAY_IMPOR_FUN_TABLE>(
                        dllname
                        , fun_table));
            } 
        }

        return true;
    } while (false);

    return false;
}

bool 
XJyaoushingan::get_thread_local_storage(
    XTLS_DATA& tls_data)
{
    do
    {
        IMAGE_DATA_DIRECTORY thread_local_table;
        PIMAGE_TLS_DIRECTORY ptd;
        GET_DATA_DIR_POINT(
            E_THREAD_LOCAL_TABLE
            , thread_local_table
            , PIMAGE_TLS_DIRECTORY
            , ptd);
          
        memcpy((PVOID)&tls_data.m_tls_dir, ptd, sizeof(IMAGE_TLS_DIRECTORY));

        DWORD callback_fun = ptd->AddressOfCallBacks - m_pe->OptionalHeader.ImageBase;
        callback_fun = rva_mem2file(callback_fun);
        DWORD* pos = (DWORD*)GET_OFFSET_BUFFER(m_fp_bufer, callback_fun);
        if (IsBadReadPtr(pos, sizeof(DWORD)))
        {
            return true;
        }

        while (*pos != 0)
        {
            tls_data.m_tls_fun_callback.push_back(*pos);
            pos++;
        }

        return true;
    } while (false);

    return false;
}

bool 
XJyaoushingan::get_load_config_table(
    XLOAD_CONFIG_TABLE& load_config)
{
    do
    {
        IMAGE_DATA_DIRECTORY load_config_table;
        PIMAGE_LOAD_CONFIG_DIRECTORY lcc;
        GET_DATA_DIR_POINT(
            E_LOAD_CONFIG_TABLE
            , load_config_table
            , PIMAGE_LOAD_CONFIG_DIRECTORY
            , lcc); 

        memcpy((PVOID)&load_config.m_load_config, lcc, sizeof(IMAGE_LOAD_CONFIG_DIRECTORY));
         
        DWORD offset = rva_mem2file(lcc->SEHandlerTable - m_pe->OptionalHeader.ImageBase); 
        DWORD* she_table = (DWORD*)GET_OFFSET_BUFFER(m_fp_bufer, offset);
        for (DWORD i = 0; i < lcc->SEHandlerCount; i++)
        {  
            DWORD fun_address = rva_mem2file(she_table[i]);
            fun_address = (DWORD)GET_OFFSET_BUFFER(m_fp_bufer, fun_address);
         
            load_config.m_seh_list.push_back(fun_address);
        } 

        return true;
    } while (false);
    return false;
}

/*
**  MZ头解析
*/
    
XMZStream::XMZStream(
    const IMAGE_DOS_HEADER& dos)
    : m_mz(NULL)
{
    init(dos);
}

XMZStream::~XMZStream()
{
    m_mz = NULL;
}

bool 
XMZStream::init(
    const IMAGE_DOS_HEADER& dos)
{
    m_mz = &dos;
    return true;
}

XString 
XMZStream::to_string()
{
    XString str;
    if (m_mz == NULL)
    {
        return str;
    }

    if (IsBadReadPtr(m_mz, sizeof(PIMAGE_DOS_HEADER)))
    {
        return str;
    }

    if (m_mz->e_magic == 0x5A4D)
    {
        str << L"MZ头" << L"\r\n";;
    }
    else
    {
        str << L"非MZ头" << L"\r\n";
        return str;
    }

    str << L"最后（部分）页中的字节数: " << m_mz->e_cblp << L"\r\n";
    str << L"文件中的全部和部分页数: " << m_mz->e_cp << L"\r\n";
    str << L"重定位表中的指针数: " << m_mz->e_crlc << L"\r\n";
    str << L"头部尺寸，以段落为单位: " << m_mz->e_cparhdr << L"\r\n";
    str << L"所需要最小附加段: " << m_mz->e_minalloc << L"\r\n";
    str << L"所需要最大附加段: " << m_mz->e_maxalloc << L"\r\n";
    str << L"初始的SS值（相对便宜）: " << m_mz->e_ss << L"\r\n";
    str << L"初始的sp值: " << m_mz->e_sp << L"\r\n";
    str << L"补码校验值: " << m_mz->e_csum << L"\r\n";
    str << L"重定位表的字节偏移值: " << m_mz->e_lfarlc << L"\r\n";
    str << L"覆盖号: " << m_mz->e_ovno << L"\r\n";
    str << L"OEM标识符: " << m_mz->e_oemid << L"\r\n";
    str << L"OEM信息: " << m_mz->e_oeminfo << L"\r\n";
    str << L"PE头相对偏移: " << m_mz->e_lfanew << L"\r\n";

    return str;
}

/*
**  PE头解析
*/ 
XFileHeadStream::XFileHeadStream(
    const IMAGE_FILE_HEADER& file_head)
    : m_file_head(NULL)
{
    init(file_head);
}

XFileHeadStream::~XFileHeadStream()
{
    m_file_head = NULL;
}

void 
XFileHeadStream::init(
    const IMAGE_FILE_HEADER& file_head)
{
    m_file_head = &file_head;
}

XString 
XFileHeadStream::to_string()
{
    XString str;
    str << L"文件头: \r\n";
    str << L"运行平台: " << Machine() << L"\r\n";
    str << L"PE中节的数量: " << NumberOfSections() << L"\r\n";
    str << L"文件创建日期和时间: " << TimeDateStamp() << L"\r\n";
    str << L"指向符号表（用于调试）: " << PointerToSymbolTable() << L"\r\n";
    str << L"符号表中的符号数量（用于调试）: " << NumberOfSymbols() << L"\r\n";
    str << L"扩展头结构长度: " << SizeOfOptionalHeader() << L"\r\n";
    str << L"文件属性: \r\n" << Characteristics() << L"\r\n";
    return str;
}

XString 
XFileHeadStream::Machine()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_file_head);

    XString str; 
    switch (m_file_head->Machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        str << L"x86平台";
        break;

    case IMAGE_FILE_MACHINE_IA64:
        str << L"IA64平台";
        break;

    case IMAGE_FILE_MACHINE_AMD64:
        str << L"AMD64平台";
        break;
    }

    return str;
}

XString 
XFileHeadStream::NumberOfSections()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_file_head);

    XString str;
    str << m_file_head->NumberOfSections;
    return str;
}

XString 
XFileHeadStream::TimeDateStamp()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_file_head);

    time_t t = m_file_head->TimeDateStamp;
    tm* local = localtime(&t);

    char buf[128] = { 0 };
    strftime(buf, 64, "%Y-%m-%d %H:%M:%S", local);

    XString str;
    str << buf;
    return str;
}

XString 
XFileHeadStream::PointerToSymbolTable()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_file_head);

    XString str;
    str << m_file_head->PointerToSymbolTable;
    return str;
}

XString 
XFileHeadStream::NumberOfSymbols()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_file_head);

    XString str;
    str << m_file_head->NumberOfSymbols;
    return str;
}

XString 
XFileHeadStream::SizeOfOptionalHeader()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_file_head);

    XString str;
    str << m_file_head->SizeOfOptionalHeader;
    return str;
}

XString 
XFileHeadStream::Characteristics()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_file_head);

    XString str;

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_RELOCS_STRIPPED)
    {
        str << L"文件中不存在重定位信息。\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_EXECUTABLE_IMAGE)
    {
        str << L"该文件是可执行的。\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_LINE_NUMS_STRIPPED)
    {
        str << L"不存在行信息。\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_LOCAL_SYMS_STRIPPED)
    {
        str << L"不存在符号信息。\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_AGGRESIVE_WS_TRIM)
    {
        str << L"调整工作集。\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_LARGE_ADDRESS_AWARE)
    {
        str << L"应用程序可以处理大于2GB的地址。\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_BYTES_REVERSED_LO)
    {
        str << L"小尾方式运行。\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_32BIT_MACHINE)
    {
        str << L"只在32位平台上运行。\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_DEBUG_STRIPPED)
    {
        str << L"不包含调试信息。\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP)
    {
        str << L"不能从可移动盘运行。\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_NET_RUN_FROM_SWAP)
    {
        str << L"不能从网络运行。\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_SYSTEM)
    {
        str << L"系统文件（可能是sys）不能直接运行。\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_DLL)
    {
        str << L"这是一个DLL文件。\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_UP_SYSTEM_ONLY)
    {
        str << L"文件不能再多处理器计算机上运行。\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_BYTES_REVERSED_HI)
    {
        str << L"大尾方式。\r\n";
    }

    return str;
}
 
XOptionHeadStream::XOptionHeadStream(
    const IMAGE_OPTIONAL_HEADER& option_head)
    : m_option_head(NULL)
{
    init(option_head);
}

XOptionHeadStream::~XOptionHeadStream()
{
    m_option_head = NULL;
}

void 
XOptionHeadStream::init(
    const IMAGE_OPTIONAL_HEADER& option_head)
{
    m_option_head = &option_head;
}

XString XOptionHeadStream::to_string()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head); 

    XString str;
    str << L"选项头: \r\n";
    str << L"文件类型: " << Magic() << L"\r\n";
    str << L"链接器主版本号: " << MajorLinkerVersion() << L"\r\n";
    str << L"链接器次要版本号: " << MinorLinkerVersion() << L"\r\n";
    str << L"代码段的大小（以字节为单位），如果有多个代码段，则为所有这些段的总和: " << SizeOfCode().to_hex_str() << L"\r\n";
    str << L"初始化数据部分的大小（以字节为单位），如果有多个初始化数据部分，则为所有此类部分的总和: " << SizeOfInitializedData().to_hex_str() << L"\r\n";
    str << L"未初始化数据部分的大小（以字节为单位），如果有多个未初始化的数据部分，则为所有此类部分的总和: " << SizeOfUninitializedData().to_hex_str() << L"\r\n";
    str << L"程序起始点: " << AddressOfEntryPoint().to_hex_str() << L"\r\n";
    str << L"代码节起始（RVA）: " << BaseOfCode().to_hex_str() << L"\r\n";
    str << L"数据节起始（RVA）: " << BaseOfData().to_hex_str() << L"\r\n";
    str << L"内存优先加载地址: " << ImageBase().to_hex_str() << L"\r\n";
    str << L"内存节对其颗粒（字节）: " << SectionAlignment().to_hex_str() << L"\r\n";
    str << L"文件节对其颗粒（字节）: " << FileAlignment().to_hex_str() << L"\r\n";
    str << L"所需操作系统主版本号: " << MajorOperatingSystemVersion() << L"\r\n";
    str << L"所需操作系统次要版本号: " << MinorOperatingSystemVersion() << L"\r\n";
    str << L"映像主版本号: " << MajorImageVersion() << L"\r\n";
    str << L"映像次要版本号: " << MinorImageVersion() << L"\r\n";
    str << L"系统的主要版本号: " << MajorSubsystemVersion() << L"\r\n";
    str << L"系统的要版要版本号: " << MinorSubsystemVersion() << L"\r\n";
    str << L"保留（必须0）: " << Win32VersionValue() << L"\r\n";
    str << L"映像大小（字节）: " << SizeOfImage().to_hex_str() << L"\r\n";
    str << L"内存整个PE文件映射尺寸: " << SizeOfHeaders().to_hex_str() << L"\r\n";
    str << L"映像文件校验和: " << CheckSum().to_hex_str() << L"\r\n";
    str << L"运行子系统: " << Subsystem().to_hex_str() << L"\r\n";
    str << L"映像属性:\r\n" << DllCharacteristics();
    str << L"初始化保留栈大小: " << SizeOfStackReserve().to_hex_str() << L"\r\n";
    str << L"初始化实际提交栈大小: " << SizeOfStackCommit().to_hex_str() << L"\r\n";
    str << L"初始化保留堆大小: " << SizeOfHeapReserve().to_hex_str() << L"\r\n";
    str << L"初始化实际提交堆大小: " << SizeOfHeapCommit().to_hex_str() << L"\r\n";
    str << L"该成员已过时: " << LoaderFlags() << L"\r\n";
    str << L"选择头数量: " << NumberOfRvaAndSizes() << L"\r\n";

    return str;
}

XString 
XOptionHeadStream::Magic()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);
    XString str;

    if (m_option_head->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        str << L"32位可执行文件";
    }
    else if (m_option_head->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        str << L"64位可执行文件";
    }
    else if (m_option_head->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        str << L"ROM映像文件";
    }

    return str;
}

XString 
XOptionHeadStream::MajorLinkerVersion()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->MajorLinkerVersion;
    return str;
}

XString 
XOptionHeadStream::MinorLinkerVersion()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->MinorLinkerVersion;
    return str;
}

XString 
XOptionHeadStream::SizeOfCode()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->SizeOfCode;
    return str;
}

XString 
XOptionHeadStream::SizeOfInitializedData()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->SizeOfInitializedData;
    return str;
}

XString 
XOptionHeadStream::SizeOfUninitializedData()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->SizeOfUninitializedData;
    return str;
}

XString 
XOptionHeadStream::AddressOfEntryPoint()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->AddressOfEntryPoint;
    return str;
}

XString 
XOptionHeadStream::BaseOfCode()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->BaseOfCode;
    return str;
}

XString 
XOptionHeadStream::BaseOfData()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->BaseOfData;
    return str;
}

XString 
XOptionHeadStream::ImageBase()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->ImageBase;
    return str;
}

XString 
XOptionHeadStream::SectionAlignment()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->SectionAlignment;
    return str;
}

XString 
XOptionHeadStream::FileAlignment()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->FileAlignment;
    return str;
}

XString 
XOptionHeadStream::MajorOperatingSystemVersion()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->MajorOperatingSystemVersion;
    return str;
}

XString 
XOptionHeadStream::MinorOperatingSystemVersion()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->MinorOperatingSystemVersion;
    return str;
}

XString 
XOptionHeadStream::MajorImageVersion()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->MajorImageVersion;
    return str;
}

XString 
XOptionHeadStream::MinorImageVersion()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->MinorImageVersion;
    return str;
}

XString 
XOptionHeadStream::MajorSubsystemVersion()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->MajorSubsystemVersion;
    return str;
}

XString 
XOptionHeadStream::MinorSubsystemVersion()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->MinorSubsystemVersion;
    return str;
}

XString 
XOptionHeadStream::Win32VersionValue()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->Win32VersionValue;
    return str;
}

XString 
XOptionHeadStream::SizeOfImage()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->SizeOfImage;
    return str;
}

XString 
XOptionHeadStream::SizeOfHeaders()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->SizeOfHeaders;
    return str;
}

XString 
XOptionHeadStream::CheckSum()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->CheckSum;
    return str;
}

XString 
XOptionHeadStream::Subsystem()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    switch (m_option_head->Subsystem)
    {
    case IMAGE_SUBSYSTEM_UNKNOWN:
        str << L"未知子系统";
        break;

    case IMAGE_SUBSYSTEM_NATIVE:
        str << L"无需子系统（设备驱动程序）";
        break;

    case IMAGE_SUBSYSTEM_WINDOWS_GUI:
        str << L"Windows图形界面程序";
        break;

    case IMAGE_SUBSYSTEM_WINDOWS_CUI:
        str << L"Windows字符模式（控制台程序）";
        break;

    case IMAGE_SUBSYSTEM_OS2_CUI:
        str << L"OS / 2 CUI子系统。";
        break;

    case IMAGE_SUBSYSTEM_POSIX_CUI:
        str << L"POSIX CUI子系统。";
        break;

    case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
        str << L"Windows CE系统。";
        break;

    case IMAGE_SUBSYSTEM_EFI_APPLICATION:
        str << L"可扩展固件接口（EFI）应用程序。";
        break;

    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
        str << L"带引导服务的EFI驱动程序。";
        break;

    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
        str << L"具有运行时服务的EFI驱动程序。";
        break;

    case IMAGE_SUBSYSTEM_EFI_ROM:
        str << L"EFI ROM映像。";
        break;

    case IMAGE_SUBSYSTEM_XBOX:
        str << L"Xbox系统。";
        break;

    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
        str << L"启动应用程序";
        break;

    default:
        break;
    }

    return str;
}

XString 
XOptionHeadStream::DllCharacteristics()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    if (m_option_head->Subsystem & 0x0001)
    {
        str << L"保留。\r\n";
    }

    if (m_option_head->Subsystem & 0x0002)
    {
        str << L"保留。\r\n";
    }

    if (m_option_head->Subsystem & 0x0008)
    {
        str << L"保留。\r\n";
    }

    if (m_option_head->Subsystem & 0x0008)
    {
        str << L"保留。\r\n";
    }

    if (m_option_head->Subsystem & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
    {
        str << L"DLL可以在加载时被重定位。\r\n";
    }

    if (m_option_head->Subsystem & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
    {
        str << L"DLL强制代码实施完整性验证。\r\n";
    }

    if (m_option_head->Subsystem & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
    {
        str << L"该映像与数据执行保护（DEP）兼容。\r\n";
    }

    if (m_option_head->Subsystem & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
    {
        str << L"可以隔离，但并不隔离此映像。\r\n";
    }

    if (m_option_head->Subsystem & IMAGE_DLLCHARACTERISTICS_NO_SEH)
    {
        str << L"映像不使用SEH。\r\n";
    }

    if (m_option_head->Subsystem & IMAGE_DLLCHARACTERISTICS_NO_BIND)
    {
        str << L"不绑定映像。\r\n";
    }

    if (m_option_head->Subsystem & 0x1000)
    {
        str << L"保留。\r\n";
    }

    if (m_option_head->Subsystem & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER)
    {
        str << L"一个WDM驱动程序。\r\n";
    }

    if (m_option_head->Subsystem & 0x4000)
    {
        str << L"保留。\r\n";
    }

    if (m_option_head->Subsystem & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)
    {
        str << L"映像是终端服务器识别的。\r\n";
    }

    return str;
}

XString 
XOptionHeadStream::SizeOfStackReserve()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->SizeOfStackReserve;
    return str;
}

XString 
XOptionHeadStream::SizeOfStackCommit()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->SizeOfStackCommit;
    return str;
}

XString 
XOptionHeadStream::SizeOfHeapReserve()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->SizeOfHeapReserve;
    return str;
}

XString 
XOptionHeadStream::SizeOfHeapCommit()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->SizeOfHeapCommit;
    return str;
}

XString 
XOptionHeadStream::LoaderFlags()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->LoaderFlags;
    return str;
}

XString 
XOptionHeadStream::NumberOfRvaAndSizes()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_option_head);

    XString str;
    str << m_option_head->NumberOfRvaAndSizes;
    return str;
}
 
XDataDirStream::XDataDirStream(
    const std::map<E_DATA_DIR_TABLE, IMAGE_DATA_DIRECTORY>& data_dir)
    : m_data_dir(NULL)
{
    init(data_dir);
}

XDataDirStream::~XDataDirStream()
{
    m_data_dir = NULL;
}

void 
XDataDirStream::init(
    const std::map<E_DATA_DIR_TABLE
    , IMAGE_DATA_DIRECTORY>& data_dir)
{
    m_data_dir = &data_dir;
}

XString 
XDataDirStream::to_string()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_data_dir); 

        WCHAR sz[][100] = {
            L"导出表: "
            , L"导入表: "
            , L"资源表: "
            , L"异常表: "
            , L"属性证书表: "
            , L"基址重定位表: "
            , L"调试信息表: "
            , L"预留表: "
            , L"全局指针寄存器表: "
            , L"线程局部存储表: "
            , L"加载配置表: "
            , L"绑定导入表: "
            , L"导入函数地址表: "
            , L"延迟导入表: "
            , L"CLR运行时头部数据表: "
            , L"系统保留: "
    };

    XString str;
    str << L"数据目录表: \r\n";
    std::map<E_DATA_DIR_TABLE, IMAGE_DATA_DIRECTORY>::const_iterator it = m_data_dir->cbegin();
    for (it; it != m_data_dir->end(); it++)
    {
        str << sz[it->first]
            << L" 大小: " << XString(it->second.Size).to_hex_str()
            << L" 虚拟地址: " << XString(it->second.VirtualAddress).to_hex_str()
            << L"\r\n";
    }

    return str;
} 

/*
**  节表
*/ 
XSectionTableStream::XSectionTableStream(
    const IMAGE_SECTION_HEADER& section_handle)
    : m_section_handle(NULL)
{
    init(section_handle);
}

XSectionTableStream::~XSectionTableStream()
{ 
}

void 
XSectionTableStream::init(
    const IMAGE_SECTION_HEADER& section_handle)
{
    m_section_handle = &section_handle;
}

XString 
XSectionTableStream::to_string(
    IMAGE_SECTION_HEADER& section)
{
    XString str;

    str << L"名称: " << Name() << L"\r\n";
    str << L"虚拟大小: " << VirtualSize().to_hex_str() << L"\r\n";
    str << L"虚拟偏移: " << VirtualAddress().to_hex_str() << L"\r\n";
    str << L"RAW大小: " << SizeOfRawData().to_hex_str() << L"\r\n";
    str << L"RAW偏移: " << PointerToRawData().to_hex_str() << L"\r\n";
    str << L"节属性: " << Characteristics() << L"\r\n";

    return str;
}

XString 
XSectionTableStream::Name()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_section_handle); 

    XString str((char*)m_section_handle->Name);
    return str;
}

XString 
XSectionTableStream::PhysicalAddress()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_section_handle);

    XString str;
    str << m_section_handle->Misc.PhysicalAddress;
    return str;
}

XString 
XSectionTableStream::VirtualSize()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_section_handle);

    XString str;
    str << m_section_handle->Misc.VirtualSize;
    return str;
}

XString 
XSectionTableStream::VirtualAddress()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_section_handle);

    XString str;
    str << m_section_handle->VirtualAddress;
    return str;
}

XString 
XSectionTableStream::SizeOfRawData()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_section_handle);

    XString str;
    str << m_section_handle->SizeOfRawData;
    return str;
}

XString 
XSectionTableStream::PointerToRawData()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_section_handle);

    XString str;
    str << m_section_handle->PointerToRawData;
    return str;
}

XString 
XSectionTableStream::PointerToRelocations()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_section_handle);

    XString str;
    str << m_section_handle->PointerToRelocations;
    return str;
}

XString 
XSectionTableStream::PointerToLinenumbers()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_section_handle);

    XString str;
    str << m_section_handle->PointerToLinenumbers;
    return str;
}

XString 
XSectionTableStream::NumberOfRelocations()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_section_handle);

    XString str;
    str << m_section_handle->NumberOfRelocations;
    return str;
}

XString 
XSectionTableStream::NumberOfLinenumbers()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_section_handle);

    XString str;
    str << m_section_handle->NumberOfLinenumbers;
    return str;
}

XString 
XSectionTableStream::Characteristics()
{
    IS_POINT_EMPTY_RET_WCSNULL(m_section_handle);

    XString str;
    str << L"节中包含";

    if (m_section_handle->Characteristics & IMAGE_SCN_CNT_CODE)
    {
        str << L"|代码";
    }

    if (m_section_handle->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
    {
        str << L"|已初始化数据";
    }

    if (m_section_handle->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
    {
        str << L"|未初始化数据";
    }

    if (m_section_handle->Characteristics & IMAGE_SCN_LNK_OTHER)
    {
        str << L"|保留供将来使用";
    }

    if (m_section_handle->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
    {
        str << L"|节数据在进程开始以后将被丢弃（如.reloc）";
    }

    if (m_section_handle->Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
    {
        str << L"|节中的数据不会经过缓存";
    }

    if (m_section_handle->Characteristics & IMAGE_SCN_MEM_NOT_PAGED)
    {
        str << L"|节数据不会被交换到磁盘";
    }

    if (m_section_handle->Characteristics & IMAGE_SCN_MEM_SHARED)
    {
        str << L"|节数据将会被不同进程所共享";
    }

    if (m_section_handle->Characteristics & IMAGE_SCN_MEM_EXECUTE)
    {
        str << L"|节有可执行属性";
    }

    if (m_section_handle->Characteristics & IMAGE_SCN_MEM_READ)
    {
        str << L"|节有可读属性";
    }

    if (m_section_handle->Characteristics & IMAGE_SCN_MEM_WRITE)
    {
        str << L"|节有可写属性";
    }

    return str;
}