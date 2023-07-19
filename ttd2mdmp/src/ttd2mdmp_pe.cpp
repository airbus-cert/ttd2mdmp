
#include "ttd2mdmp_pe.h"

// Helpers

// get the VA of the modules NT Header
PIMAGE_DOS_HEADER get_dos_header(
    TTD_Context* ctx,
    GuestAddress ui_library_address)
{
  MemoryBuffer memory_buffer;
  TBuffer buf;

  buf.size = sizeof(IMAGE_DOS_HEADER);
  buf.dst_buffer = malloc(sizeof(IMAGE_DOS_HEADER));
  ctx->Cursor->ICursor->QueryMemoryBuffer(
      ctx->Cursor, &memory_buffer, (GuestAddress) ui_library_address, &buf, 0);
  return (PIMAGE_DOS_HEADER) buf.dst_buffer;
}

PIMAGE_NT_HEADERS get_nt_headers(
    TTD_Context* ctx,
    GuestAddress ui_library_address,
    PIMAGE_DOS_HEADER dos_header)
{
  MemoryBuffer memory_buffer;
  TBuffer buf;

  PIMAGE_NT_HEADERS p_nt_headers =
      (PIMAGE_NT_HEADERS) (ui_library_address + dos_header->e_lfanew);
  buf.size = sizeof(IMAGE_NT_HEADERS);
  buf.dst_buffer = malloc(sizeof(IMAGE_NT_HEADERS));
  ctx->Cursor->ICursor->QueryMemoryBuffer(
      ctx->Cursor, &memory_buffer, (GuestAddress) p_nt_headers, &buf, 0);

  return (PIMAGE_NT_HEADERS) buf.dst_buffer;
}

PIMAGE_DATA_DIRECTORY get_data_directory(PIMAGE_NT_HEADERS p_nt_headers)
{
  return (PIMAGE_DATA_DIRECTORY) &p_nt_headers->OptionalHeader
      .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
}

PIMAGE_EXPORT_DIRECTORY get_export_directory(
    TTD_Context* ctx,
    GuestAddress ui_library_address,
    PIMAGE_DATA_DIRECTORY p_data_directory)
{
  MemoryBuffer memory_buffer;
  TBuffer buf;

  // get the VA of the export directory
  GuestAddress address =
      (GuestAddress) (ui_library_address + p_data_directory->VirtualAddress);

  buf.size = sizeof(IMAGE_EXPORT_DIRECTORY);
  buf.dst_buffer = malloc(sizeof(IMAGE_EXPORT_DIRECTORY));
  ctx->Cursor->ICursor->QueryMemoryBuffer(
      ctx->Cursor, &memory_buffer, address, &buf, 0);

  return (PIMAGE_EXPORT_DIRECTORY) buf.dst_buffer;
}

DWORD* get_function_names(
    TTD_Context* ctx,
    GuestAddress ui_name_array,
    PIMAGE_EXPORT_DIRECTORY p_export_directory)
{
  MemoryBuffer memory_buffer;
  TBuffer buf;

  buf.size = sizeof(DWORD*) * p_export_directory->NumberOfFunctions;
  buf.dst_buffer = malloc(buf.size);
  ctx->Cursor->ICursor->QueryMemoryBuffer(
      ctx->Cursor, &memory_buffer, ui_name_array, &buf, 0);

  return (DWORD*) buf.dst_buffer;
}

GuestAddress get_given_function_address(
    TTD_Context* ctx,
    TTD_Function* function,
    GuestAddress ui_library_address,
    GuestAddress ui_name_ordinals,
    GuestAddress ui_address_array,
    DWORD* p_function_names,
    PIMAGE_EXPORT_DIRECTORY p_export_directory)
{
  MemoryBuffer memory_buffer;
  TBuffer buf;

  buf.size = MAX_FUNCTION_NAME;
  char* name_a = new char[buf.size];
  for (int j = 0; j < (int) p_export_directory->NumberOfNames; j++)
  {
    buf.dst_buffer = name_a;
    ctx->Cursor->ICursor->QueryMemoryBuffer(
        ctx->Cursor,
        &memory_buffer,
        (GuestAddress) (ui_library_address + p_function_names[j]),
        &buf,
        0);

    // convert name to WCHAR
    WCHAR name_w[MAX_FUNCTION_NAME];
    mbstowcs_s(nullptr, name_w, name_a, MAX_FUNCTION_NAME);

    if (wcscmp(name_w, function->name) == 0)
    {
      WORD ordinal;
      DWORD offset;

      buf.size = sizeof(WORD);
      buf.dst_buffer = &ordinal;
      ctx->Cursor->ICursor->QueryMemoryBuffer(
          ctx->Cursor,
          &memory_buffer,
          (GuestAddress) (ui_name_ordinals + j * sizeof(WORD)),
          &buf,
          0);

      buf.size = sizeof(DWORD);
      buf.dst_buffer = &offset;
      ctx->Cursor->ICursor->QueryMemoryBuffer(
          ctx->Cursor,
          &memory_buffer,
          (GuestAddress) (ui_address_array + ordinal * sizeof(DWORD)),
          &buf,
          0);

      GuestAddress address = (GuestAddress) (ui_library_address + offset);

      delete[] (name_a);

      return address;
    }
  }

  return 0;
}

int resolve_function_address(TTD_Context* ctx, TTD_Function* function)
{
  // Init the address to 0 ie not found
  function->address = 0;

  // Save current cursor position
  TTD_POSITION saved_position = *ctx->Cursor->ICursor->GetPosition(
      ctx->Cursor, 0);

  // Search if the module is used by the process
  size_t module_count = ctx->Engine->IReplayEngine->GetModuleLoadedEventCount(
      ctx->Engine);
  const TTD_Replay_ModuleLoadedEvent* modules =
      ctx->Engine->IReplayEngine->GetModuleLoadedEventList(ctx->Engine);

  unsigned int i = 0;
  WCHAR* cpy = new WCHAR[MAX_FUNCTION_NAME];
  while (i < module_count)
  {
    WCHAR* tmp = cpy;
    wcscpy_s(tmp, MAX_FUNCTION_NAME, modules[i].info->path);

    WCHAR* buf = NULL;
    while (*tmp) buf = wcstok_s(tmp, L"\\", &tmp);

    WCHAR* context = nullptr;
    buf = wcstok_s(buf, L".", &context);

    if (wcscmp(buf, function->module) == 0)
      break;

    i++;
  };

  delete[] (cpy);
  // If the module is not found, return an error
  if (i == module_count)
  {
    fwprintf(stderr, L"Module %s not found\n", function->module);
    return 1;
  }

  TTD_POSITION pos = {modules[i].pos.major, modules[i].pos.minor};
  ctx->Cursor->ICursor->SetPosition(ctx->Cursor, &pos);

  UINT_PTR ui_library_address = (UINT_PTR) modules[i].info->base_addr;
  UINT_PTR ui_address_array = 0;
  UINT_PTR ui_name_array = 0;
  UINT_PTR ui_name_ordinals = 0;

  PIMAGE_DOS_HEADER dos_header = get_dos_header(ctx, ui_library_address);

  PIMAGE_NT_HEADERS p_nt_headers = get_nt_headers(
      ctx, ui_library_address, dos_header);

  PIMAGE_DATA_DIRECTORY p_data_directory = get_data_directory(p_nt_headers);

  PIMAGE_EXPORT_DIRECTORY p_export_directory = get_export_directory(
      ctx, ui_library_address, p_data_directory);

  // get the VA for the array of addresses
  ui_address_array =
      (ui_library_address + p_export_directory->AddressOfFunctions);

  // get the VA for the array of name pointers
  ui_name_array = (ui_library_address + p_export_directory->AddressOfNames);

  // get the VA for the array of name ordinals
  ui_name_ordinals =
      (ui_library_address + p_export_directory->AddressOfNameOrdinals);

  DWORD* p_function_names = get_function_names(
      ctx, ui_name_array, p_export_directory);

  function->address = get_given_function_address(
      ctx,
      function,
      ui_library_address,
      ui_name_ordinals,
      ui_address_array,
      p_function_names,
      p_export_directory);

  free(dos_header);
  free(p_nt_headers);
  free(p_export_directory);
  free(p_function_names);

  ctx->Cursor->ICursor->SetPosition(ctx->Cursor, &saved_position);
  return ERROR_SUCCESS;
}
