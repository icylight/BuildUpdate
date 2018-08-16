
#include "stdafx.h"

#include <lzmahelper.h>

#include <base/file/file.h>
#include <base/file/filedata.h>
#include <base/json/json_writer.h>
#include <base/json/values.h>
#include <base/md5.h>
#include <base/string/string_number_conversions.h>

#include <common/Buffer.h>
#include <common/strconv.h>

#pragma pack(1)  //指定按2字节对齐
typedef struct _TA_LZMA_HEADER {
  char magic[5]; /*TALZMA*/
  unsigned char props[5];
  size_t originalsize;
  size_t compresssize;
} TA_LZMA_HEADER;
#pragma pack()  //取消指定对齐，恢复缺省对齐

#define VERSION L"1.0.0.23"
#define RUN ""
#define TIPS L""

#define OPENURL ""

#ifdef _DEBUG
#define URL_FIX L"http://localhost:8000/MissEvanFM"
#else
#define URL_FIX L"http://static.missevan.com/app/win/"
#endif  // _DEBUG

#define UPDATE_INFO_FILENAME L"update.json"

static wchar_t* sz_jmp_filename[] = {L"BuildUpdate.exe", L"TaLzma.exe",
                                     UPDATE_INFO_FILENAME};

#define JMP_FILE_COUNT (sizeof(sz_jmp_filename) / sizeof(wchar_t*))

class App {
 public:
  App(LPCTSTR path, LPCTSTR version) : m_path(path) {
    m_files = new ListValue;
    if (lstrlen(TIPS) > 0) {
      char* utf8tips = NULL;
      lo_W2Utf8(&utf8tips, TIPS);

      if (utf8tips) {
        m_value.SetString("tips", utf8tips);
        free(utf8tips);
      }
    }
    m_value.SetString("version", version);
    m_value.SetString("run", RUN);
    m_value.SetString("openurl", OPENURL);
    m_value.Set("files", m_files);
  }

  ~App() {}

  static LPCWSTR GetFileNameExt(LPCWSTR file) {
    for (int i = lstrlen(file) - 1; i > 0; i--) {
      if (file[i] == '.') {
        return file + i + 1;
        break;
      }
    }
    return file;
  }

  wchar_t* ToUrlFormat(LPCSTR szData) {
    int nLen = lstrlenA(szData);
    std::wstring strUrlf;
    wchar_t data[4];
    data[3] = 0;

    for (int i = 0; i < nLen; i++) {
      if ((szData[i] >= 'A' && szData[i] <= 'Z') ||
          (szData[i] >= 'a' && szData[i] <= 'z') ||
          (szData[i] >= '0' && szData[i] <= '9') || szData[i] == '_' ||
          szData[i] == '-' || szData[i] == '.' ||
          szData[i] == '/')  //标准ASCII字符
      {
        /*ii = lstrlenA(UrlUtf8);
        UrlUtf8[ii] = (BYTE)utf8[i];
        UrlUtf8[ii + 1] = 0;*/
        strUrlf.append(1, szData[i]);
      } else {
        wsprintf(data, L"%%%02X", (BYTE)(szData[i]));
        strUrlf.append(data);
        // lstrcatA(UrlUtf8, data);
      }
    }

    return wcsdup(strUrlf.c_str());
  }

  bool IsJmpFile(const wchar_t* filename) {
    for (int i = 0; i < JMP_FILE_COUNT; i++) {
      if (lstrcmpiW(filename, sz_jmp_filename[i]) == 0) {
        return true;
      }
    }
    return false;
  }

  size_t FileMD5(uint8* data, size_t length, std::string& file_md5) {
    if (length < 5) {
      return 0;
    }

    CBuffer dstfile_buf;

    //解压数据
    TA_LZMA_HEADER* header = (TA_LZMA_HEADER*)data;
    if (memcmp(header->magic, "TALZMA", 5) == 0) {
      if (header->compresssize + sizeof(TA_LZMA_HEADER) <= length) {
        size_t osize = header->originalsize;
        size_t csize = header->compresssize;
        size_t propsize = LZMA_PROPS_SIZE;
        unsigned char* m_original_data = (unsigned char*)malloc(osize);
        if (m_original_data) {
          int status = LzmaUncompress(m_original_data, &osize,
                                      data + sizeof(TA_LZMA_HEADER),
                                      (size_t*)&csize, header->props, propsize);
          if (status == SZ_OK) {
            base::MD5Digest digest = {0};
            base::MD5Sum(m_original_data, osize, &digest);
            file_md5 = base::MD5DigestToBase16(digest);
            return osize;
          }
        }
      }
    }

    return 0;
  }

  bool AddFile(LPCTSTR path, LPCTSTR folder, LPCTSTR filename) {
    base::CFile file;
    if (file.Open(base::kFileRead, path)) {
      base::CFileData fd;
      if (fd.Read(file)) {
        base::MD5Digest digest = {0};
        base::MD5Sum(fd.GetData(), fd.GetSize(), &digest);

        DictionaryValue* vlaue = new DictionaryValue;

        std::wstring uri, url = URL_FIX, filepath = folder;

        vlaue->SetInteger("size", fd.GetSize());

        vlaue->SetString("md5", base::MD5DigestToBase16(digest));

        uri = folder;
        uri += filename;
        char* mbfolder = NULL;  //::WcToMb(uri.c_str());
        lo_W2C(&mbfolder, uri.c_str());
        wchar_t* utf8uri = ToUrlFormat(mbfolder);
        free(mbfolder);

        vlaue->SetString("url", url + utf8uri);

        free(utf8uri);

        if (lstrcmpi(GetFileNameExt(filename), L"talzma") == 0) {
          std::string file_md5;
          size_t file_size = FileMD5(fd.GetData(), fd.GetSize(), file_md5);
          if (!file_size || file_md5.empty()) {
            _tprintf(_T("%s\\%s decompress failed!\n"), folder, filename);
            return false;
          }

          vlaue->SetString("file_md5", file_md5);
          vlaue->SetInteger("file_size", file_size);

          TCHAR tpath[MAX_PATH];
          lstrcpy(tpath, filename);
          wchar_t* text = (wchar_t*)GetFileNameExt(tpath);
          if (text) {
            *(text - 1) = 0;
          }
          filepath += tpath;
        } else {
          filepath += filename;
        }
        vlaue->SetString("path", filepath);
        m_files->Append(vlaue);
        return true;
      }
    }
    return false;
  }

  bool Write() {
    bool ret = false;
    std::string json;
    base::JSONWriter::Write(&m_value, false, &json);
    int length = 0;
    if ((length = json.length()) > 0) {
      base::CFile file;
      std::wstring m_updatefile = m_path;
      m_updatefile += UPDATE_INFO_FILENAME;
      if (file.Open(base::kFileCreate, m_updatefile.c_str())) {
        ret = file.Write((unsigned char*)json.c_str(), length);
        file.Close();
      }
    }
    return ret;
  }

  ListValue* m_files;
  DictionaryValue m_value;

  std::wstring m_path;
};

App* m_app = NULL;

bool FindFolder(LPCTSTR folder, LPCTSTR appendfolder) {
  TCHAR findpath[MAX_PATH];
  lstrcpy(findpath, folder);
  lstrcat(findpath, L"*");

  WIN32_FIND_DATA fd;
  ZeroMemory(&fd, sizeof(WIN32_FIND_DATA));

  HANDLE hSearch;
  TCHAR tmpPath[MAX_PATH], append[MAX_PATH];

  hSearch = FindFirstFile(findpath, &fd);

  if (hSearch == INVALID_HANDLE_VALUE) return false;

  do {
    if (fd.cFileName[0] == L'.') {
      continue;
    }

    // Check is directory
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      lstrcpy(tmpPath, folder);
      lstrcat(tmpPath, fd.cFileName);
      lstrcat(tmpPath, L"\\");

      lstrcpy(append, appendfolder);
      lstrcat(append, fd.cFileName);
      lstrcat(append, L"/");

      FindFolder(tmpPath, append);
    } else {
      if (!m_app->IsJmpFile(fd.cFileName)) {
        lstrcpy(tmpPath, folder);
        lstrcat(tmpPath, fd.cFileName);

        m_app->AddFile(tmpPath, appendfolder, fd.cFileName);
      }
    }
  } while (FindNextFile(hSearch, &fd));

  FindClose(hSearch);

  return true;
}

std::wstring GetLastErrorAsString() {
  // Get the error message, if any.
  DWORD errorMessageID = ::GetLastError();
  if (errorMessageID == 0)
    return std::wstring();  // No error message has been recorded

  LPTSTR messageBuffer = nullptr;
  size_t size = FormatMessage(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      (LPTSTR)&messageBuffer, 0, NULL);

  std::wstring message(messageBuffer, size);

  // Free the buffer.
  LocalFree(messageBuffer);

  return message;
}

int _tmain(int argc, _TCHAR* argv[]) {
  TCHAR path[MAX_PATH];
  ::GetModuleFileName(NULL, path, MAX_PATH);
  for (int i = lstrlen(path) - 1; i > 0; i--) {
    if (path[i] == '\\') {
      path[i + 1] = 0;
      break;
    }
  }

  const TCHAR* szVersion = VERSION;
  if (argc > 1) {
    szVersion = argv[1];
  }

  m_app = new App(path, szVersion);
  FindFolder(path, L"");

  if (!m_app->Write()) {
    std::wstring str = GetLastErrorAsString();
    _tprintf(L"Error: %s\n", str.c_str());
  }

  delete m_app;

  return 0;
}
