#include "pch.h"
#include "XJyaoushingan.h"
#include <time.h>

#define INIT_FILE_HEAD_STREAM if (m_file_head == NULL) return L""; 
#define INIT_OPTION_HEAD_STREAM if (m_option_head == NULL) return L"";
#define INIT_DATA_DIR_STREAM if (m_data_dir == NULL) return L""; 
#define INIT_SECTION_HANDLE_STREAM if (m_section_handle == NULL) return L"";
    
#define NOT_INIT() \
if (m_fp_bufer == NULL || IsBadReadPtr(m_fp_bufer, sizeof(LPVOID)))\
{\
return false;\
}

#define GET_OFFSET_BUFFER(p, o) (LPVOID)((DWORD)p + o) 
#define PE_SIGN 4


WCHAR g_resource_name[16][16] = { L"���", L"λͼ", L"ͼ��", L"�˵�", L"�Ի���",
                                L"�ַ���", L"����Ŀ¼", L"����", L"��ݼ�", L"δ��ʽ����Դ",
                                L"��Ϣ��", L"�����", L"", L"ͼ����", L"", L"�汾" };

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
        if (!get_data_dir(E_IMPORT_TAB, import_name))
        {
            break;
        }

        //         IMAGE_DATA_DIRECTORY import_fun;
        //         if (!get_data_dir(E_IMPORT_ADDRESS_TABLE, import_fun))
        //         {
        //             break;
        //         }

        DWORD offset_name = rva_mem2file(import_name.VirtualAddress);
        if (offset_name == 0)
        {
            break;
        }

        //         DWORD offset_fun = rva_mem2file(import_fun.VirtualAddress);
        //         if (offset_fun == 0)
        //         {
        //             break;
        //         }

        PIMAGE_IMPORT_DESCRIPTOR import_descriptor 
            = (PIMAGE_IMPORT_DESCRIPTOR)GET_OFFSET_BUFFER(m_fp_bufer, offset_name);
        /*        DWORD pos2 = (DWORD)GET_OFFSET_BUFFER(m_fp_bufer, offset_fun);*/

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
        if (!get_data_dir(E_EXPORT_TAB, exportable))
        {
            break;
        }

        DWORD offset = rva_mem2file(exportable.VirtualAddress);
        if (offset == 0)
        {
            break;
        }

        PIMAGE_EXPORT_DIRECTORY export_descriptor = (PIMAGE_EXPORT_DIRECTORY)GET_OFFSET_BUFFER(m_fp_bufer, offset);
        if (export_descriptor == NULL)
        {
            break;
        }

        DWORD name_pos = rva_mem2file(export_descriptor->Name);
        char* name = (char*)GET_OFFSET_BUFFER(m_fp_bufer, name_pos);
        XString dll_name(name);

        offset = rva_mem2file(export_descriptor->AddressOfNameOrdinals);
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
        if (!get_data_dir(E_RESOURCE_TAB, recource))
        {
            break;
        }

        DWORD offset = rva_mem2file(recource.VirtualAddress);
        if (offset == 0)
        {
            break;
        }

        PIMAGE_RESOURCE_DIRECTORY rd_root
            = (PIMAGE_RESOURCE_DIRECTORY)GET_OFFSET_BUFFER(m_fp_bufer, offset);
        if (rd_root == NULL)
        {
            break;
        }

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
                  
                //����ڶ�����Դ�ı�ʶ�������ֻ����ַ���
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

                //���������� 
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
        if (!get_data_dir(E_DELAY_IMPORT_TABLE, delay_load_importable))
        {
            break;
        }

        DWORD offset = rva_mem2file(delay_load_importable.VirtualAddress);
        if (offset == 0)
        {
            break;
        }

        PIMAGE_DELAYLOAD_DESCRIPTOR pdd  
            = (PIMAGE_DELAYLOAD_DESCRIPTOR)GET_OFFSET_BUFFER(m_fp_bufer, offset);
        if (pdd == NULL)
        {
            break;
        }

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

/*
**  MZͷ����
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
        str << L"MZͷ" << L"\r\n";;
    }
    else
    {
        str << L"��MZͷ" << L"\r\n";
        return str;
    }

    str << L"��󣨲��֣�ҳ�е��ֽ���: " << m_mz->e_cblp << L"\r\n";
    str << L"�ļ��е�ȫ���Ͳ���ҳ��: " << m_mz->e_cp << L"\r\n";
    str << L"�ض�λ���е�ָ����: " << m_mz->e_crlc << L"\r\n";
    str << L"ͷ���ߴ磬�Զ���Ϊ��λ: " << m_mz->e_cparhdr << L"\r\n";
    str << L"����Ҫ��С���Ӷ�: " << m_mz->e_minalloc << L"\r\n";
    str << L"����Ҫ��󸽼Ӷ�: " << m_mz->e_maxalloc << L"\r\n";
    str << L"��ʼ��SSֵ����Ա��ˣ�: " << m_mz->e_ss << L"\r\n";
    str << L"��ʼ��spֵ: " << m_mz->e_sp << L"\r\n";
    str << L"����У��ֵ: " << m_mz->e_csum << L"\r\n";
    str << L"�ض�λ����ֽ�ƫ��ֵ: " << m_mz->e_lfarlc << L"\r\n";
    str << L"���Ǻ�: " << m_mz->e_ovno << L"\r\n";
    str << L"OEM��ʶ��: " << m_mz->e_oemid << L"\r\n";
    str << L"OEM��Ϣ: " << m_mz->e_oeminfo << L"\r\n";
    str << L"PEͷ���ƫ��: " << m_mz->e_lfanew << L"\r\n";

    return str;
}

/*
**  PEͷ����
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
    str << L"�ļ�ͷ: \r\n";
    str << L"����ƽ̨: " << Machine() << L"\r\n";
    str << L"PE�нڵ�����: " << NumberOfSections() << L"\r\n";
    str << L"�ļ��������ں�ʱ��: " << TimeDateStamp() << L"\r\n";
    str << L"ָ����ű����ڵ��ԣ�: " << PointerToSymbolTable() << L"\r\n";
    str << L"���ű��еķ������������ڵ��ԣ�: " << NumberOfSymbols() << L"\r\n";
    str << L"��չͷ�ṹ����: " << SizeOfOptionalHeader() << L"\r\n";
    str << L"�ļ�����: \r\n" << Characteristics() << L"\r\n";
    return str;
}

XString 
XFileHeadStream::Machine()
{
    INIT_FILE_HEAD_STREAM

    XString str; 
    switch (m_file_head->Machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        str << L"x86ƽ̨";
        break;

    case IMAGE_FILE_MACHINE_IA64:
        str << L"IA64ƽ̨";
        break;

    case IMAGE_FILE_MACHINE_AMD64:
        str << L"AMD64ƽ̨";
        break;
    }

    return str;
}

XString 
XFileHeadStream::NumberOfSections()
{
    INIT_FILE_HEAD_STREAM

    XString str;
    str << m_file_head->NumberOfSections;
    return str;
}

XString 
XFileHeadStream::TimeDateStamp()
{
    INIT_FILE_HEAD_STREAM

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
    INIT_FILE_HEAD_STREAM

    XString str;
    str << m_file_head->PointerToSymbolTable;
    return str;
}

XString 
XFileHeadStream::NumberOfSymbols()
{
    INIT_FILE_HEAD_STREAM

    XString str;
    str << m_file_head->NumberOfSymbols;
    return str;
}

XString 
XFileHeadStream::SizeOfOptionalHeader()
{
    INIT_FILE_HEAD_STREAM

    XString str;
    str << m_file_head->SizeOfOptionalHeader;
    return str;
}

XString 
XFileHeadStream::Characteristics()
{
    INIT_FILE_HEAD_STREAM

    XString str;

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_RELOCS_STRIPPED)
    {
        str << L"�ļ��в������ض�λ��Ϣ��\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_EXECUTABLE_IMAGE)
    {
        str << L"���ļ��ǿ�ִ�еġ�\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_LINE_NUMS_STRIPPED)
    {
        str << L"����������Ϣ��\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_LOCAL_SYMS_STRIPPED)
    {
        str << L"�����ڷ�����Ϣ��\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_AGGRESIVE_WS_TRIM)
    {
        str << L"������������\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_LARGE_ADDRESS_AWARE)
    {
        str << L"Ӧ�ó�����Դ������2GB�ĵ�ַ��\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_BYTES_REVERSED_LO)
    {
        str << L"Сβ��ʽ���С�\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_32BIT_MACHINE)
    {
        str << L"ֻ��32λƽ̨�����С�\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_DEBUG_STRIPPED)
    {
        str << L"������������Ϣ��\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP)
    {
        str << L"���ܴӿ��ƶ������С�\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_NET_RUN_FROM_SWAP)
    {
        str << L"���ܴ��������С�\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_SYSTEM)
    {
        str << L"ϵͳ�ļ���������sys������ֱ�����С�\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_DLL)
    {
        str << L"����һ��DLL�ļ���\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_UP_SYSTEM_ONLY)
    {
        str << L"�ļ������ٶദ��������������С�\r\n";
    }

    if (m_file_head->SizeOfOptionalHeader & IMAGE_FILE_BYTES_REVERSED_HI)
    {
        str << L"��β��ʽ��\r\n";
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
    INIT_OPTION_HEAD_STREAM

        XString str;
    str << L"ѡ��ͷ: \r\n";
    str << L"�ļ�����: " << Magic() << L"\r\n";
    str << L"���������汾��: " << MajorLinkerVersion() << L"\r\n";
    str << L"��������Ҫ�汾��: " << MinorLinkerVersion() << L"\r\n";
    str << L"����εĴ�С�����ֽ�Ϊ��λ��������ж������Σ���Ϊ������Щ�ε��ܺ�: " << SizeOfCode().to_hex_str() << L"\r\n";
    str << L"��ʼ�����ݲ��ֵĴ�С�����ֽ�Ϊ��λ��������ж����ʼ�����ݲ��֣���Ϊ���д��ಿ�ֵ��ܺ�: " << SizeOfInitializedData().to_hex_str() << L"\r\n";
    str << L"δ��ʼ�����ݲ��ֵĴ�С�����ֽ�Ϊ��λ��������ж��δ��ʼ�������ݲ��֣���Ϊ���д��ಿ�ֵ��ܺ�: " << SizeOfUninitializedData().to_hex_str() << L"\r\n";
    str << L"������ʼ��: " << AddressOfEntryPoint().to_hex_str() << L"\r\n";
    str << L"�������ʼ��RVA��: " << BaseOfCode().to_hex_str() << L"\r\n";
    str << L"���ݽ���ʼ��RVA��: " << BaseOfData().to_hex_str() << L"\r\n";
    str << L"�ڴ����ȼ��ص�ַ: " << ImageBase().to_hex_str() << L"\r\n";
    str << L"�ڴ�ڶ���������ֽڣ�: " << SectionAlignment().to_hex_str() << L"\r\n";
    str << L"�ļ��ڶ���������ֽڣ�: " << FileAlignment().to_hex_str() << L"\r\n";
    str << L"�������ϵͳ���汾��: " << MajorOperatingSystemVersion() << L"\r\n";
    str << L"�������ϵͳ��Ҫ�汾��: " << MinorOperatingSystemVersion() << L"\r\n";
    str << L"ӳ�����汾��: " << MajorImageVersion() << L"\r\n";
    str << L"ӳ���Ҫ�汾��: " << MinorImageVersion() << L"\r\n";
    str << L"ϵͳ����Ҫ�汾��: " << MajorSubsystemVersion() << L"\r\n";
    str << L"ϵͳ��Ҫ��Ҫ�汾��: " << MinorSubsystemVersion() << L"\r\n";
    str << L"����������0��: " << Win32VersionValue() << L"\r\n";
    str << L"ӳ���С���ֽڣ�: " << SizeOfImage().to_hex_str() << L"\r\n";
    str << L"�ڴ�����PE�ļ�ӳ��ߴ�: " << SizeOfHeaders().to_hex_str() << L"\r\n";
    str << L"ӳ���ļ�У���: " << CheckSum().to_hex_str() << L"\r\n";
    str << L"������ϵͳ: " << Subsystem().to_hex_str() << L"\r\n";
    str << L"ӳ������:\r\n" << DllCharacteristics();
    str << L"��ʼ������ջ��С: " << SizeOfStackReserve().to_hex_str() << L"\r\n";
    str << L"��ʼ��ʵ���ύջ��С: " << SizeOfStackCommit().to_hex_str() << L"\r\n";
    str << L"��ʼ�������Ѵ�С: " << SizeOfHeapReserve().to_hex_str() << L"\r\n";
    str << L"��ʼ��ʵ���ύ�Ѵ�С: " << SizeOfHeapCommit().to_hex_str() << L"\r\n";
    str << L"�ó�Ա�ѹ�ʱ: " << LoaderFlags() << L"\r\n";
    str << L"ѡ��ͷ����: " << NumberOfRvaAndSizes() << L"\r\n";

    return str;
}

XString 
XOptionHeadStream::Magic()
{
    INIT_OPTION_HEAD_STREAM 
    XString str;

    if (m_option_head->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        str << L"32λ��ִ���ļ�";
    }
    else if (m_option_head->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        str << L"64λ��ִ���ļ�";
    }
    else if (m_option_head->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        str << L"ROMӳ���ļ�";
    }

    return str;
}

XString 
XOptionHeadStream::MajorLinkerVersion()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->MajorLinkerVersion;
    return str;
}

XString 
XOptionHeadStream::MinorLinkerVersion()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->MinorLinkerVersion;
    return str;
}

XString 
XOptionHeadStream::SizeOfCode()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->SizeOfCode;
    return str;
}

XString 
XOptionHeadStream::SizeOfInitializedData()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->SizeOfInitializedData;
    return str;
}

XString 
XOptionHeadStream::SizeOfUninitializedData()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->SizeOfUninitializedData;
    return str;
}

XString 
XOptionHeadStream::AddressOfEntryPoint()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->AddressOfEntryPoint;
    return str;
}

XString 
XOptionHeadStream::BaseOfCode()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->BaseOfCode;
    return str;
}

XString 
XOptionHeadStream::BaseOfData()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->BaseOfData;
    return str;
}

XString 
XOptionHeadStream::ImageBase()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->ImageBase;
    return str;
}

XString 
XOptionHeadStream::SectionAlignment()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->SectionAlignment;
    return str;
}

XString 
XOptionHeadStream::FileAlignment()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->FileAlignment;
    return str;
}

XString 
XOptionHeadStream::MajorOperatingSystemVersion()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->MajorOperatingSystemVersion;
    return str;
}

XString 
XOptionHeadStream::MinorOperatingSystemVersion()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->MinorOperatingSystemVersion;
    return str;
}

XString 
XOptionHeadStream::MajorImageVersion()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->MajorImageVersion;
    return str;
}

XString 
XOptionHeadStream::MinorImageVersion()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->MinorImageVersion;
    return str;
}

XString 
XOptionHeadStream::MajorSubsystemVersion()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->MajorSubsystemVersion;
    return str;
}

XString 
XOptionHeadStream::MinorSubsystemVersion()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->MinorSubsystemVersion;
    return str;
}

XString 
XOptionHeadStream::Win32VersionValue()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->Win32VersionValue;
    return str;
}

XString 
XOptionHeadStream::SizeOfImage()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->SizeOfImage;
    return str;
}

XString 
XOptionHeadStream::SizeOfHeaders()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->SizeOfHeaders;
    return str;
}

XString 
XOptionHeadStream::CheckSum()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->CheckSum;
    return str;
}

XString 
XOptionHeadStream::Subsystem()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    switch (m_option_head->Subsystem)
    {
    case IMAGE_SUBSYSTEM_UNKNOWN:
        str << L"δ֪��ϵͳ";
        break;

    case IMAGE_SUBSYSTEM_NATIVE:
        str << L"������ϵͳ���豸��������";
        break;

    case IMAGE_SUBSYSTEM_WINDOWS_GUI:
        str << L"Windowsͼ�ν������";
        break;

    case IMAGE_SUBSYSTEM_WINDOWS_CUI:
        str << L"Windows�ַ�ģʽ������̨����";
        break;

    case IMAGE_SUBSYSTEM_OS2_CUI:
        str << L"OS / 2 CUI��ϵͳ��";
        break;

    case IMAGE_SUBSYSTEM_POSIX_CUI:
        str << L"POSIX CUI��ϵͳ��";
        break;

    case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
        str << L"Windows CEϵͳ��";
        break;

    case IMAGE_SUBSYSTEM_EFI_APPLICATION:
        str << L"����չ�̼��ӿڣ�EFI��Ӧ�ó���";
        break;

    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
        str << L"�����������EFI��������";
        break;

    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
        str << L"��������ʱ�����EFI��������";
        break;

    case IMAGE_SUBSYSTEM_EFI_ROM:
        str << L"EFI ROMӳ��";
        break;

    case IMAGE_SUBSYSTEM_XBOX:
        str << L"Xboxϵͳ��";
        break;

    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
        str << L"����Ӧ�ó���";
        break;

    default:
        break;
    }

    return str;
}

XString 
XOptionHeadStream::DllCharacteristics()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    if (m_option_head->Subsystem & 0x0001)
    {
        str << L"������\r\n";
    }

    if (m_option_head->Subsystem & 0x0002)
    {
        str << L"������\r\n";
    }

    if (m_option_head->Subsystem & 0x0008)
    {
        str << L"������\r\n";
    }

    if (m_option_head->Subsystem & 0x0008)
    {
        str << L"������\r\n";
    }

    if (m_option_head->Subsystem & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
    {
        str << L"DLL�����ڼ���ʱ���ض�λ��\r\n";
    }

    if (m_option_head->Subsystem & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
    {
        str << L"DLLǿ�ƴ���ʵʩ��������֤��\r\n";
    }

    if (m_option_head->Subsystem & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
    {
        str << L"��ӳ��������ִ�б�����DEP�����ݡ�\r\n";
    }

    if (m_option_head->Subsystem & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
    {
        str << L"���Ը��룬�����������ӳ��\r\n";
    }

    if (m_option_head->Subsystem & IMAGE_DLLCHARACTERISTICS_NO_SEH)
    {
        str << L"ӳ��ʹ��SEH��\r\n";
    }

    if (m_option_head->Subsystem & IMAGE_DLLCHARACTERISTICS_NO_BIND)
    {
        str << L"����ӳ��\r\n";
    }

    if (m_option_head->Subsystem & 0x1000)
    {
        str << L"������\r\n";
    }

    if (m_option_head->Subsystem & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER)
    {
        str << L"һ��WDM��������\r\n";
    }

    if (m_option_head->Subsystem & 0x4000)
    {
        str << L"������\r\n";
    }

    if (m_option_head->Subsystem & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)
    {
        str << L"ӳ�����ն˷�����ʶ��ġ�\r\n";
    }

    return str;
}

XString 
XOptionHeadStream::SizeOfStackReserve()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->SizeOfStackReserve;
    return str;
}

XString 
XOptionHeadStream::SizeOfStackCommit()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->SizeOfStackCommit;
    return str;
}

XString 
XOptionHeadStream::SizeOfHeapReserve()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->SizeOfHeapReserve;
    return str;
}

XString 
XOptionHeadStream::SizeOfHeapCommit()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->SizeOfHeapCommit;
    return str;
}

XString 
XOptionHeadStream::LoaderFlags()
{
    INIT_OPTION_HEAD_STREAM

    XString str;
    str << m_option_head->LoaderFlags;
    return str;
}

XString 
XOptionHeadStream::NumberOfRvaAndSizes()
{
    INIT_OPTION_HEAD_STREAM

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
    INIT_DATA_DIR_STREAM

        WCHAR sz[][100] = {
            L"������: "
            , L"�����: "
            , L"��Դ��: "
            , L"�쳣��: "
            , L"����֤���: "
            , L"��ַ�ض�λ��: "
            , L"������Ϣ��: "
            , L"Ԥ����: "
            , L"ȫ��ָ��Ĵ�����: "
            , L"�ֲ߳̾��洢��: "
            , L"�������ñ�: "
            , L"�󶨵����: "
            , L"���뺯����ַ��: "
            , L"�ӳٵ����: "
            , L"CLR����ʱͷ�����ݱ�: "
            , L"ϵͳ����: "
    };

    XString str;
    str << L"����Ŀ¼��: \r\n";
    std::map<E_DATA_DIR_TABLE, IMAGE_DATA_DIRECTORY>::const_iterator it = m_data_dir->cbegin();
    for (it; it != m_data_dir->end(); it++)
    {
        str << sz[it->first]
            << L" ��С: " << XString(it->second.Size).to_hex_str()
            << L" �����ַ: " << XString(it->second.VirtualAddress).to_hex_str()
            << L"\r\n";
    }

    return str;
} 

/*
**  �ڱ�
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

    str << L"����: " << Name() << L"\r\n";
    str << L"�����С: " << VirtualSize().to_hex_str() << L"\r\n";
    str << L"����ƫ��: " << VirtualAddress().to_hex_str() << L"\r\n";
    str << L"RAW��С: " << SizeOfRawData().to_hex_str() << L"\r\n";
    str << L"RAWƫ��: " << PointerToRawData().to_hex_str() << L"\r\n";
    str << L"������: " << Characteristics() << L"\r\n";

    return str;
}

XString 
XSectionTableStream::Name()
{
    INIT_SECTION_HANDLE_STREAM

    XString str((char*)m_section_handle->Name);
    return str;
}

XString 
XSectionTableStream::PhysicalAddress()
{
    INIT_SECTION_HANDLE_STREAM

    XString str;
    str << m_section_handle->Misc.PhysicalAddress;
    return str;
}

XString 
XSectionTableStream::VirtualSize()
{
    INIT_SECTION_HANDLE_STREAM

    XString str;
    str << m_section_handle->Misc.VirtualSize;
    return str;
}

XString 
XSectionTableStream::VirtualAddress()
{
    INIT_SECTION_HANDLE_STREAM

    XString str;
    str << m_section_handle->VirtualAddress;
    return str;
}

XString 
XSectionTableStream::SizeOfRawData()
{
    INIT_SECTION_HANDLE_STREAM

    XString str;
    str << m_section_handle->SizeOfRawData;
    return str;
}

XString 
XSectionTableStream::PointerToRawData()
{
    INIT_SECTION_HANDLE_STREAM

    XString str;
    str << m_section_handle->PointerToRawData;
    return str;
}

XString 
XSectionTableStream::PointerToRelocations()
{
    INIT_SECTION_HANDLE_STREAM

    XString str;
    str << m_section_handle->PointerToRelocations;
    return str;
}

XString 
XSectionTableStream::PointerToLinenumbers()
{
    INIT_SECTION_HANDLE_STREAM

    XString str;
    str << m_section_handle->PointerToLinenumbers;
    return str;
}

XString 
XSectionTableStream::NumberOfRelocations()
{
    INIT_SECTION_HANDLE_STREAM

    XString str;
    str << m_section_handle->NumberOfRelocations;
    return str;
}

XString 
XSectionTableStream::NumberOfLinenumbers()
{
    INIT_SECTION_HANDLE_STREAM

    XString str;
    str << m_section_handle->NumberOfLinenumbers;
    return str;
}

XString 
XSectionTableStream::Characteristics()
{
    XString str;
    str << L"���а���";

    if (m_section_handle->Characteristics & IMAGE_SCN_CNT_CODE)
    {
        str << L"|����";
    }

    if (m_section_handle->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
    {
        str << L"|�ѳ�ʼ������";
    }

    if (m_section_handle->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
    {
        str << L"|δ��ʼ������";
    }

    if (m_section_handle->Characteristics & IMAGE_SCN_LNK_OTHER)
    {
        str << L"|����������ʹ��";
    }

    if (m_section_handle->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
    {
        str << L"|�������ڽ��̿�ʼ�Ժ󽫱���������.reloc��";
    }

    if (m_section_handle->Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
    {
        str << L"|���е����ݲ��ᾭ������";
    }

    if (m_section_handle->Characteristics & IMAGE_SCN_MEM_NOT_PAGED)
    {
        str << L"|�����ݲ��ᱻ����������";
    }

    if (m_section_handle->Characteristics & IMAGE_SCN_MEM_SHARED)
    {
        str << L"|�����ݽ��ᱻ��ͬ����������";
    }

    if (m_section_handle->Characteristics & IMAGE_SCN_MEM_EXECUTE)
    {
        str << L"|���п�ִ������";
    }

    if (m_section_handle->Characteristics & IMAGE_SCN_MEM_READ)
    {
        str << L"|���пɶ�����";
    }

    if (m_section_handle->Characteristics & IMAGE_SCN_MEM_WRITE)
    {
        str << L"|���п�д����";
    }

    return str;
}