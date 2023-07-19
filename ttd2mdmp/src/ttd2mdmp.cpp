#include "ttd_utils.h"

#include <minidumpapiset.h>
#include <winternl.h>
#include <ctime>

#define WRITE(X, Y)                       \
  WriteFile(hOut, X, (DWORD) Y, &res, 0); \
  dwCurrentRva += res;

#define TRY(X, Y) \
  if (X)          \
    return Error(Y);

#define _TRY(X, Y) \
  if (X)           \
    return _Error(Y);

void AddData(
    void* pData,
    size_t DataLength,
    std::vector<char>* pCurrentData,
    DWORD* pCurrentDataRva)
{
  for (int idx = 0; idx < DataLength; idx++)
  {
    pCurrentData->push_back(((char*) pData)[idx]);
  }
  *pCurrentDataRva += (DWORD) DataLength;
}

void AddDataW(
    wchar_t* pDataW,
    size_t DataLength,
    std::vector<char>* pCurrentData,
    DWORD* pCurrentDataRva)
{
  // Add size as DWORD
  AddData(&DataLength, 4, pCurrentData, pCurrentDataRva);

  // Add string with null byte and WCHAR size
  AddData(pDataW, (DataLength + 1) * 2, pCurrentData, pCurrentDataRva);
}

void _Error(const char* str)
{
  fprintf(stderr, "%s (%d)\n", str, GetLastError());
  return;
}

int Error(const char* str)
{
  _Error(str);
  return 1;
}

void GenerateMiniDump(TTD_Context* ttd, TTD_Replay_IThreadView* ThreadView)
{
  TTD_POSITION* CurrentPosition = ttd->Cursor->ICursor->GetPosition(
      ttd->Cursor, 0);
  TTD_POSITION* SavedPosition = new TTD_POSITION{
      CurrentPosition->major, CurrentPosition->minor};
  TTD_POSITION* CallbackPosition = ThreadView->IThreadView->GetPosition(
      ThreadView);
  ttd->Cursor->ICursor->SetPosition(ttd->Cursor, CallbackPosition);

  // Query memory ranges
  size_t ModuleCount = ttd->Engine->IReplayEngine->GetModuleLoadedEventCount(
      ttd->Engine);
  const TTD_Replay_ModuleLoadedEvent* ttdModules =
      ttd->Engine->IReplayEngine->GetModuleLoadedEventList(ttd->Engine);

  // Query thread info
  size_t ThreadCount = ttd->Engine->IReplayEngine->GetThreadCount(ttd->Engine);
  // -1 because the last thread is the duplicate of the current thread
  ThreadCount--;
  const TTD_Replay_ThreadInfo* ttdThreads =
      ttd->Engine->IReplayEngine->GetThreadList(ttd->Engine);

  // Query module info
  std::vector<TTD_MEMORY_RANGE*>* ttdMemoryRanges;
  ttd->GetHeapRanges(CallbackPosition, &ttdMemoryRanges);
  size_t HeapCount = ttdMemoryRanges->size();
  size_t MemoryCount = HeapCount + ModuleCount;

  std::wstring OutFilename = std::wstring(ttd->Out);
  std::wstring sCount = std::to_wstring(ttd->dwCount);
  OutFilename.insert(OutFilename.end() - 5, sCount.begin(), sCount.end());

  // Create new MDMP file
  HANDLE hOut = CreateFileW(
      OutFilename.c_str(),
      FILE_SHARE_WRITE,
      0,
      NULL,
      CREATE_ALWAYS,
      FILE_ATTRIBUTE_NORMAL,
      NULL);
  _TRY(hOut == INVALID_HANDLE_VALUE, "Failed to create file");

  // Init MDMP directories
  const size_t DirectoriesSize = 4;
  MINIDUMP_DIRECTORY mdmpDirectories[DirectoriesSize];

  // Init MDMP sizes
  size_t ThreadsSize = sizeof(MINIDUMP_THREAD) * ThreadCount;
  size_t ThreadListSize = sizeof(ULONG32) + ThreadsSize;
  size_t ModulesSize = sizeof(MINIDUMP_MODULE) * ModuleCount;
  size_t ModuleListSize = sizeof(ULONG32) + ModulesSize;
  size_t MemorySize = sizeof(MINIDUMP_MEMORY64_LIST) * MemoryCount;
  size_t MemoryListSize = sizeof(ULONG64) + sizeof(RVA64) + MemorySize;

  // Init MDMP positions
  DWORD res;
  DWORD dwCurrentRva = 0;
  DWORD dwStartDirectories = sizeof(MINIDUMP_HEADER);
  DWORD dwStartThreads = dwStartDirectories +
                         sizeof(MINIDUMP_DIRECTORY) * DirectoriesSize;
  DWORD dwStartModules = (DWORD) (dwStartThreads + ThreadListSize);
  DWORD dwStartSystem = (DWORD) (dwStartModules + ModuleListSize);
  DWORD dwStartMemories = dwStartSystem + sizeof(MINIDUMP_SYSTEM_INFO);
  DWORD dwStartData = (DWORD) (dwStartMemories + MemoryListSize);

  DWORD dwCurrentDataRva = 0;
  std::vector<char> CurrentData;

  // Set header
  MINIDUMP_HEADER mdmpHeader;
  mdmpHeader.Signature = 0x504d444d;  // MDMP
  mdmpHeader.Version = 0xa015a793;
  mdmpHeader.NumberOfStreams = DirectoriesSize;
  mdmpHeader.StreamDirectoryRva = dwStartDirectories;
  mdmpHeader.CheckSum = 0;
  mdmpHeader.Reserved = 0;
  mdmpHeader.TimeDateStamp = (ULONG32) std::time(0);
  mdmpHeader.Flags = MiniDumpWithFullMemory;

  // Set directories
  mdmpDirectories[0].StreamType = ThreadListStream;
  mdmpDirectories[0].Location = {
      (unsigned long) ThreadListSize, dwStartThreads};

  mdmpDirectories[1].StreamType = ModuleListStream;
  mdmpDirectories[1].Location = {
      (unsigned long) ModuleListSize, dwStartModules};

  mdmpDirectories[2].StreamType = SystemInfoStream;
  mdmpDirectories[2].Location = {
      (unsigned long) sizeof(MINIDUMP_SYSTEM_INFO), dwStartSystem};

  mdmpDirectories[3].StreamType = Memory64ListStream;
  mdmpDirectories[3].Location = {
      (unsigned long) MemoryListSize, dwStartMemories};

  // Parse threads
  MINIDUMP_THREAD_LIST* mdmpThreadList = (MINIDUMP_THREAD_LIST*) malloc(
      ThreadListSize);
  _TRY(!mdmpThreadList, "Error, cannot malloc");
  mdmpThreadList->NumberOfThreads = (ULONG32) ThreadCount;

  for (unsigned int i = 0; i < ThreadCount; i++)
  {
    TTD_Replay_ThreadInfo ttdThread = ttdThreads[i];
    MINIDUMP_THREAD* mdmpThread = &(
        (MINIDUMP_THREAD*) mdmpThreadList->Threads)[i];

    mdmpThread->ThreadId = ttdThread.threadid;
    mdmpThread->Teb = ttd->Cursor->ICursor->GetTebAddress(
        ttd->Cursor, ttdThread.threadid);
    PNT_TIB TebData = (PNT_TIB) malloc(sizeof(NT_TIB));
    ttd->DumpMemory((void**) &TebData, mdmpThread->Teb, sizeof(NT_TIB));

    PCONTEXT ContextData = (PCONTEXT) malloc(0xA70);
    _TRY(!ContextData, "Error, cannot malloc");
    ttd->Cursor->ICursor->GetCrossPlatformContext(
        ttd->Cursor, ContextData, ttdThread.threadid);

    mdmpThread->Stack.StartOfMemoryRange = ContextData->Rsp;
    mdmpThread->Stack.Memory.DataSize =
        (ULONG32) ((GuestAddress) (TebData->StackBase) - ContextData->Rsp);
    // RVA = 0, but add the stack range to the memory ranges
    // Round the allocated stack size. Most of the time, 0x1000 ie 64KB for a
    // small stack
    // Thanks to the round, we dump a little bit more of memory on the stack
    mdmpThread->Stack.Memory.Rva = 0;
    ULONG32 StackSize = (mdmpThread->Stack.Memory.DataSize & 0x11111000) +
                        0x1000;
    ttdMemoryRanges->push_back(new TTD_MEMORY_RANGE{
        (GuestAddress) (TebData->StackBase) - StackSize,
        (GuestAddress) (TebData->StackBase)});

    mdmpThread->ThreadContext.DataSize = sizeof(CONTEXT);  // TODO arch??
    mdmpThread->ThreadContext.Rva = dwStartData + dwCurrentDataRva;
    AddData(
        ContextData,
        mdmpThread->ThreadContext.DataSize,
        &CurrentData,
        &dwCurrentDataRva);

    free(ContextData);

    // No info
    mdmpThread->SuspendCount = 0;
    mdmpThread->PriorityClass = 0;
    mdmpThread->Priority = 0;
  }

  // Parse modules
  MINIDUMP_MODULE_LIST* mdmpModuleList = (MINIDUMP_MODULE_LIST*) malloc(
      ModuleListSize);
  _TRY(!mdmpModuleList, "Error, cannot malloc");
  mdmpModuleList->NumberOfModules = (ULONG32) ModuleCount;

  for (unsigned int i = 0; i < ModuleCount; i++)
  {
    MINIDUMP_MODULE* mdmpModule = &(
        (MINIDUMP_MODULE*) mdmpModuleList->Modules)[i];
    TTD_Replay_ModuleLoadedEvent ttdModule = ttdModules[i];

    mdmpModule->ModuleNameRva = dwStartData + dwCurrentDataRva;
    AddDataW(
        ttdModule.info->path,
        ttdModule.info->path_len,
        &CurrentData,
        &dwCurrentDataRva);

    mdmpModule->BaseOfImage = ttdModule.info->base_addr;
    mdmpModule->SizeOfImage = (ULONG32) ttdModule.info->image_size;
    mdmpModule->CheckSum = ttdModule.info->checkSum;
    mdmpModule->TimeDateStamp = ttdModule.info->timestampEnd;

    ttdMemoryRanges->push_back(new TTD_MEMORY_RANGE{
        mdmpModule->BaseOfImage,
        mdmpModule->BaseOfImage + mdmpModule->SizeOfImage});

    // TODO
    memset(&mdmpModule->VersionInfo, 0, sizeof(VS_FIXEDFILEINFO));
    memset(&mdmpModule->CvRecord, 0, sizeof(MINIDUMP_LOCATION_DESCRIPTOR));
    memset(&mdmpModule->MiscRecord, 0, sizeof(MINIDUMP_LOCATION_DESCRIPTOR));
    mdmpModule->Reserved0 = 0;
    mdmpModule->Reserved1 = 0;
  }

  // Parse memory
  MINIDUMP_MEMORY64_LIST* mdmpMemoryList = (MINIDUMP_MEMORY64_LIST*) malloc(
      MemoryListSize);
  _TRY(!mdmpMemoryList, "Error, cannot malloc");
  mdmpMemoryList->NumberOfMemoryRanges = MemoryCount;
  mdmpMemoryList->BaseRva = dwStartData + CurrentData.size();  // TESTME

  for (int i = 0; i < MemoryCount; i++)
  {
    MINIDUMP_MEMORY_DESCRIPTOR64* descriptor = &(
        mdmpMemoryList->MemoryRanges)[i];
    TTD_MEMORY_RANGE* range = ttdMemoryRanges->at(i);

    descriptor->StartOfMemoryRange = range->start;
    descriptor->DataSize = range->end - range->start;

    LPVOID Data = malloc(descriptor->DataSize);
    _TRY(!Data, "Error, Cannot malloc");

    ttd->DumpMemory(
        &Data, descriptor->StartOfMemoryRange, descriptor->DataSize);
    AddData(Data, descriptor->DataSize, &CurrentData, &dwCurrentDataRva);

    if (i >= HeapCount)
      delete range;

    free(Data);
  }

  // Parse system info
  MINIDUMP_SYSTEM_INFO mdmpSystemInfo;
  memset(&mdmpSystemInfo, 0, sizeof(MINIDUMP_SYSTEM_INFO));

  SYSTEM_INFO* pSystemInfo = ttd->Engine->IReplayEngine->GetSystemInfo(
      ttd->Engine);
  // mdmpSystemInfo.ProcessorArchitecture = pSystemInfo->wProcessorArchitecture;
  mdmpSystemInfo.ProcessorArchitecture = 9;  // FIXME
  mdmpSystemInfo.ProcessorLevel = pSystemInfo->wProcessorLevel;
  mdmpSystemInfo.ProcessorRevision = pSystemInfo->wProcessorRevision;
  mdmpSystemInfo.NumberOfProcessors = (UCHAR) pSystemInfo->dwNumberOfProcessors;
  mdmpSystemInfo.ProductType = (UCHAR) pSystemInfo->dwProcessorType;

  // Write everything
  WRITE(&mdmpHeader, sizeof(MINIDUMP_HEADER));

  if (dwCurrentRva != dwStartDirectories)
    return _Error("Incorect dwStartDirectories");
  for (int i = 0; i < DirectoriesSize; i++)
  {
    WRITE(&mdmpDirectories[i], sizeof(MINIDUMP_DIRECTORY));
  }

  if (dwCurrentRva != dwStartThreads)
    return _Error("Incorect dwStartThreads");
  WRITE(mdmpThreadList, ThreadListSize);

  if (dwCurrentRva != dwStartModules)
    return _Error("Incorect dwStartModules");
  WRITE(mdmpModuleList, ModuleListSize);

  if (dwCurrentRva != dwStartSystem)
    return _Error("Incorect dwStartSystem");
  WRITE(&mdmpSystemInfo, sizeof(MINIDUMP_SYSTEM_INFO));

  if (dwCurrentRva != dwStartMemories)
    return _Error("Incorect dwStartMemory");
  WRITE(mdmpMemoryList, MemoryListSize);

  if (dwCurrentRva != dwStartData)
    return _Error("Incorect dwStartData");
  char* pCurrentData = static_cast<char*>(&CurrentData[0]);
  WRITE(pCurrentData, CurrentData.size());

  free(mdmpThreadList);
  free(mdmpModuleList);
  free(mdmpMemoryList);
  delete ttdMemoryRanges;

  wprintf(L"Minidump %s generated with success\n", OutFilename.c_str());

  ttd->dwCount++;
  ttd->Cursor->ICursor->SetPosition(ttd->Cursor, SavedPosition);
  return;
}

void GenerateMiniDumpCallback(
    unsigned long long callback_value,
    GuestAddress FunctionAddress,
    GuestAddress ReturnAddress,
    TTD_Replay_IThreadView* ThreadView)
{
  TTD_Context* ctx = (TTD_Context*) callback_value;
  // Filter function address
  if (FunctionAddress == ctx->CallbackAddress)
  {
    GenerateMiniDump(ctx, ThreadView);
  }
}

int wmain(int argc, wchar_t** argv)
{
  if (argc != 4)
  {
    printf("Error: need 3 args\n");
    return 1;
  }

  // Init context
  TTD_Context ttd(argv[1], argv[2]);

  // Parse argv[2]
  BOOL bIsCursor, bIsFunction;
  bIsCursor = !!wcsstr(argv[3], L":");
  bIsFunction = !!wcsstr(argv[3], L"!");

  // Cursor mode
  if (bIsCursor)
  {
    Position position;
    wchar_t* end;
    position.major = wcstoull(argv[3], &end, 16);
    position.minor = wcstoull(end + 1, NULL, 16);
    // Set position
    if (position.major)
      ttd.Cursor->ICursor->SetPosition(ttd.Cursor, &position);
    else
      ttd.Cursor->ICursor->SetPosition(
          ttd.Cursor, ttd.Engine->IReplayEngine->GetLastPosition(ttd.Engine));

    GenerateMiniDump(&ttd, nullptr);
  }

  // Function mode
  else if (bIsFunction)
  {
    ttd.CallbackAddress = ttd.GetAddress(argv[3]);
    ttd.Cursor->ICursor->SetCallReturnCallback(
        ttd.Cursor, GenerateMiniDumpCallback, (unsigned long long) &ttd);

    ttd.ReplayThreads();

    // restore cursor
    ttd.Cursor->ICursor->SetCallReturnCallback(ttd.Cursor, 0, 0);
    ttd.CallbackAddress = 0;
  }

  else
    return Error("Cannot parse position or function with the argument");
}
