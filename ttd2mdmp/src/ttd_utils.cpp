#include <stdio.h>
#include <windows.h>

#include "crypto.h"
#include "ttd2mdmp_pe.h"
#include "ttd_utils.h"

int init_ttd_engine(TTD_Replay_ReplayEngine** Engine, const WCHAR* filename)
{
  HINSTANCE h_ttd_replay_library;
  PROC_Initiate InitiateReplayEngineHandshake;
  PROC_Create CreateReplayEngineWithHandshake;
  BYTE source[48];
  char destination[336];
  sha256_ctx ctx;
  unsigned char digest[SHA256_LEN];

  h_ttd_replay_library = LoadLibrary(TEXT("TTDReplay.dll"));

  if (h_ttd_replay_library == NULL)
  {
    fwprintf(stderr, L"TTDReplay.dll not found\n");
    return 1;
  }

  InitiateReplayEngineHandshake = (PROC_Initiate) GetProcAddress(
      h_ttd_replay_library, "InitiateReplayEngineHandshake");
  CreateReplayEngineWithHandshake = (PROC_Create) GetProcAddress(
      h_ttd_replay_library, "CreateReplayEngineWithHandshake");

  int result = InitiateReplayEngineHandshake("DbgEng", source);

  strncpy_s(destination, (char*) source, 0x2F);
  for (int i = 0; i < 2; ++i)
  {
    strncat_s(
        destination,
        &A_SCOPE_OF_LICENSE[0x66 * ((source[i] - 48) % 0x11ui64)],
        0x65ui64);
  }
  strncat_s(
      destination,
      &A_TTD_ENGINE_KEY[79 * ((source[2] - 48i64) % 0xBui64)],
      0x4Eui64);

  sha256_init(&ctx);
  sha256_update(
      &ctx, (unsigned char*) destination, (DWORD) strlen(destination));
  sha256_final(digest, &ctx);

  size_t sha_b64_size;
  char* sha_b64 = base64_encode(digest, 32, &sha_b64_size);
  char tmp[0x30];
  memset(tmp, 0, 0x30);
  memcpy(tmp, sha_b64, sha_b64_size);

  void* instance;
  result = CreateReplayEngineWithHandshake(tmp, &instance, VERSION_GUID);
  *Engine = (TTD_Replay_ReplayEngine*) instance;

  if ((*Engine)->IReplayEngine->Initialize((*Engine), filename) != TRUE)
  {
    fwprintf(stderr, L"Failed to initialize ReplayEngine\n");
    return 1;
  }

  // Generate if needed the idx file of the trace file. This file is needed by
  // TTDReplay.dll to call some API endpoints like GetCrossPlatformContext
  build_index_from_engine(*Engine);
  if (check_idx_file(filename) != ERROR_SUCCESS)
  {
    fprintf(stderr, "Failed to generate index file\n");
    return 1;
  }

  return ERROR_SUCCESS;
}

char* base64_encode(
    const unsigned char* data,
    size_t input_length,
    size_t* output_length)
{
  *output_length = 4 * ((input_length + 2) / 3);

  char* encoded_data = (char*) malloc(*output_length);
  if (encoded_data == NULL)
    return NULL;

  for (int i = 0, j = 0; i < input_length;)
  {
    uint32_t octet_a = i < input_length ? (unsigned char) data[i++] : 0;
    uint32_t octet_b = i < input_length ? (unsigned char) data[i++] : 0;
    uint32_t octet_c = i < input_length ? (unsigned char) data[i++] : 0;

    uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

    encoded_data[j++] = ENCODING_TABLE[(triple >> 3 * 6) & 0x3F];
    encoded_data[j++] = ENCODING_TABLE[(triple >> 2 * 6) & 0x3F];
    encoded_data[j++] = ENCODING_TABLE[(triple >> 1 * 6) & 0x3F];
    encoded_data[j++] = ENCODING_TABLE[(triple >> 0 * 6) & 0x3F];
  }

  // no padding
  for (int i = 0; i < MOD_TABLE[input_length % 3]; i++)
    encoded_data[*output_length - 1 - i] = '\x00';

  return encoded_data;
}

int check_idx_file(const WCHAR* filename)
{
  // Assumes that the filename is the one of the trace file
  // TODO use magic bytes instead of extension
  size_t len = wcslen(filename);
  if (len < 3)
    return 1;

  WCHAR* idx_path = (WCHAR*) calloc(MAX_PATH, sizeof(WCHAR));
  if (!idx_path)
  {
    fprintf(stderr, "Error cannot calloc\n");
    return 1;
  }

  memset(idx_path, 0, MAX_PATH);
  wcscpy_s(idx_path, MAX_PATH, filename);
  idx_path[len - 3] = L'i';
  idx_path[len - 2] = L'd';
  idx_path[len - 1] = L'x';

  HANDLE fd = CreateFile(
      idx_path,
      GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_EXISTING,
      FILE_FLAG_SEQUENTIAL_SCAN,
      NULL);

  free(idx_path);
  if (fd == INVALID_HANDLE_VALUE)
    return 1;

  return ERROR_SUCCESS;
}

void dummy_callback() {}
void build_index_from_engine(TTD_Replay_ReplayEngine* Engine)
{
  Engine->IReplayEngine->BuildIndex(Engine, &dummy_callback);
}

TTD_Function::TTD_Function(WCHAR* FullName)
{
  this->module = wcstok_s(FullName, L"!", &this->name);
  this->address = 0;
}

TTD_Context::TTD_Context(WCHAR* InFilename, WCHAR* OutFilename)
{
  this->Out = std::wstring(OutFilename);

  // Init TTD
  init_ttd_engine(&this->Engine, InFilename);
  this->Cursor = this->Engine->IReplayEngine->NewCursor(
      this->Engine, GUID_CURSOR);

  InitHeap();
  dwCount = 0;
}

GuestAddress TTD_Context::GetAddress(TTD_Function* function)
{
  if (!function->address)
    resolve_function_address(this, function);

  return function->address;
}

GuestAddress TTD_Context::GetAddress(WCHAR* FullName)
{
  TTD_Function Function(FullName);
  return GetAddress(&Function);
}

void TTD_Context::InitHeap()
{
  printf("Mapping the heap...\n");
  HeapMap = new std::vector<TTD_EVENT*>;

  WCHAR sNtAllocateVirtualMemory[] = L"ntdll!NtAllocateVirtualMemory";
  WCHAR sNtFreeVirtualMemory[] = L"ntdll!NtFreeVirtualMemory";
  NtAllocateVirtualMemory = this->GetAddress(sNtAllocateVirtualMemory);
  NtFreeVirtualMemory = this->GetAddress(sNtFreeVirtualMemory);
  CallbackType = 0;

  // set callback
  Cursor->ICursor->SetCallReturnCallback(
      Cursor, InitHeapCallback, (unsigned long long) this);

  ReplayThreads();

  // restore cursor
  Cursor->ICursor->SetCallReturnCallback(Cursor, 0, 0);
  CallbackAddress = 0;

  wprintf(L"-> Found %u heap allocations\n", (ULONG32) HeapMap->size());
}

void TTD_Context::ReplayThreads()
{
  size_t thread_created_count =
      Engine->IReplayEngine->GetThreadCreatedEventCount(Engine);
  const TTD_Replay_ThreadCreatedEvent* threads_created =
      Engine->IReplayEngine->GetThreadCreatedEventList(Engine);

  // loop through all the threads
  TTD_POSITION start;
  TTD_POSITION* last = Engine->IReplayEngine->GetLastPosition(Engine);
  TTD_Replay_ICursorView_ReplayResult replayrez;
  for (int i = 0; i < thread_created_count; i++)
  {
    start.major = threads_created[i].pos.major;
    start.minor = threads_created[i].pos.minor;

    // set cursor to thread start
    Cursor->ICursor->SetPosition(Cursor, &start);

    TTD_POSITION previous;
    unsigned long long step_count;

    for (;;)
    {
      TTD_POSITION* now = Cursor->ICursor->GetPosition(Cursor, 0);
      Cursor->ICursor->ReplayForward(Cursor, &replayrez, last, StepForward);
      step_count = replayrez.stepCount;

      if (replayrez.stepCount < StepForward)
      {
        Cursor->ICursor->SetPosition(Cursor, &previous);
        Cursor->ICursor->ReplayForward(
            Cursor, &replayrez, last, step_count - 1);
        break;
      }
      memcpy(
          &previous, Cursor->ICursor->GetPosition(Cursor, 0), sizeof(previous));
    }
  }
}

void TTD_Context::DumpMemory(void** out, GuestAddress start, size_t size)
{
  MemoryBuffer memory_buffer;
  TBuffer buf = {*out, size};

  Cursor->ICursor->QueryMemoryBuffer(Cursor, &memory_buffer, start, &buf, 0);
}

void InitHeapCallback(
    unsigned long long callback_value,
    GuestAddress addr_func,
    GuestAddress addr_ret,
    struct TTD_Replay_IThreadView* thread_info)
{
  TTD_Context* ctx = (TTD_Context*) callback_value;
  BOOL match = addr_func == ctx->NtAllocateVirtualMemory ||
               addr_func == ctx->NtFreeVirtualMemory ||
               addr_func == ctx->ReturnAddress;
  if (!match)
    return;

  // Set the cursor at the callback position
  TTD_POSITION save = *ctx->Cursor->ICursor->GetPosition(ctx->Cursor, 0);
  TTD_POSITION* current = thread_info->IThreadView->GetPosition(thread_info);
  ctx->Cursor->ICursor->SetPosition(ctx->Cursor, current);

  if (addr_func == ctx->NtAllocateVirtualMemory)
  {
    TTD_EVENT* event = new TTD_EVENT{
        new TTD_MEMORY_RANGE, new TTD_POSITION, new TTD_POSITION};

    // Fetch context
    PCONTEXT pContext = (PCONTEXT) malloc(0xA70);
    if (!pContext)
      return;

    ctx->Cursor->ICursor->GetCrossPlatformContext(
        ctx->Cursor,
        pContext,
        thread_info->IThreadView->GetThreadInfo(thread_info)->threadid);

    // size of VirtualAlloc in [r9] for this syscall
    void* tmp = &event->range->end;
    ctx->DumpMemory(&tmp, pContext->R9, sizeof(void*));

    // returned value will be in [rdx] for this syscall
    ctx->ReturnValue = pContext->Rdx;

    ctx->HeapMap->push_back(event);

    ctx->ReturnAddress = addr_ret;
    ctx->CallbackType = 1;

    free(pContext);
  }

  else if (addr_func == ctx->NtFreeVirtualMemory)
  {
    PCONTEXT pContext = (PCONTEXT) malloc(0xA70);
    if (!pContext)
      return;

    ctx->Cursor->ICursor->GetCrossPlatformContext(
        ctx->Cursor,
        pContext,
        thread_info->IThreadView->GetThreadInfo(thread_info)->threadid);

    // arg is in [rdx] for this syscall
    GuestAddress* pAddress = new GuestAddress;
    ctx->DumpMemory((void**) &pAddress, pContext->Rdx, sizeof(void*));

    int i = 0;
    for (; i < ctx->HeapMap->size(); i++)
    {
      // If the event is not finished, and the range matches
      // TODO Here we also scan all the allocated areas that weren't freed
      if (ctx->HeapMap->at(i)->end->major == -1 &&
          ctx->HeapMap->at(i)->end->minor == -1 &&
          ctx->HeapMap->at(i)->range->start == *pAddress)
        break;
    }

    if (i < ctx->HeapMap->size())
    {
      ctx->HeapMap->at(i)->end->major = current->major;
      ctx->HeapMap->at(i)->end->minor = current->minor;
    }

    ctx->ReturnAddress = addr_ret;
    ctx->CallbackType = 2;

    delete pAddress;
    free(pContext);
  }

  else if (ctx->ReturnAddress == addr_func)
  {
    if (ctx->CallbackType == 1)
    {
      GuestAddress* pReturned = new GuestAddress;
      ctx->DumpMemory((void**) &pReturned, ctx->ReturnValue, sizeof(void*));

      TTD_EVENT* event = ctx->HeapMap->at(ctx->HeapMap->size() - 1);
      event->range->start = *pReturned;
      event->range->end += *pReturned;
      event->start->major = current->major;
      event->start->minor = current->minor;
      event->end->major = -1;
      event->end->minor = -1;

      delete pReturned;
    }

    ctx->ReturnAddress = 0;
    ctx->ReturnValue = 0;
    ctx->CallbackType = 0;
  }

  // Reset cursor
  ctx->Cursor->ICursor->SetPosition(ctx->Cursor, &save);
}

void TTD_Context::GetHeapRanges(
    TTD_POSITION* Position,
    std::vector<TTD_MEMORY_RANGE*>** Out)
{
  auto HeapRanges = new std::vector<TTD_MEMORY_RANGE*>;

  for (auto& event : *HeapMap)
  {
    TTD_POSITION* start = event->start;
    TTD_POSITION* end = event->end;

    // Test if position is between start and end
    if ((start->major < Position->major || (start->major == Position->major &&
                                            start->minor <= Position->minor)) &&
        (end->major > Position->major ||
         (end->major == Position->major && end->minor >= Position->minor)))
    {
      // Add the memory range to the MemoryMap
      HeapRanges->push_back(event->range);
    }
  }

  *Out = HeapRanges;
}
