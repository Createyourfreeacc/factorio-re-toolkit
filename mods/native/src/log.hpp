#pragma once
#include <cstdio>

#define FH_LOG(fmt, ...) \
  std::fprintf(stderr, "[factorio_hooks] " fmt "\n", ##__VA_ARGS__)
