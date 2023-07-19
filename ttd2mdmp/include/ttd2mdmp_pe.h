#pragma once

#include "ttd_utils.h"

/*
  Function:  resolve_function_address
  --------------------
  Fetches the address of a given function in the PE headers of the loaded
  modules If not found, returns -1
 */
int resolve_function_address(TTD_Context* ctx, TTD_Function* function);