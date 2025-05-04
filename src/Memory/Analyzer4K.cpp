#include "Memory/Analyzer4K.hpp"

Analyzer4K::Analyzer4K(int num_ranks) : num_ranks(num_ranks) {}

int inline Analyzer4K::check_time(volatile char *a1, volatile char *a2) {
  (void)*a1;
  (void)*a2;
  clflushopt(a1);
  clflushopt(a2);
  uint64_t before, after;
  before = rdtscp();
  lfence();
  for (size_t i = 0; i < 10; i++) {
    (void)*a1;
    (void)*a2;
    clflushopt(a1);
    clflushopt(a2);
    mfence();
  }
  after = rdtscp();
  return (int)((after - before) / 10);
}

bool Analyzer4K::should_conflict(uint64_t ofsta, uint64_t ofstb) {
  return num_ranks == 1 ? (__builtin_parityl(ofsta & 0x2040UL) ==
                               __builtin_parityl(ofstb & 0x2040UL) &&
                           __builtin_parityl(ofsta & 0x24000UL) ==
                               __builtin_parityl(ofstb & 0x24000UL) &&
                           __builtin_parityl(ofsta & 0x48000UL) ==
                               __builtin_parityl(ofstb & 0x48000UL) &&
                           __builtin_parityl(ofsta & 0x90000UL) ==
                               __builtin_parityl(ofstb & 0x90000UL))
                        : (__builtin_parityl(ofsta & 0x2040UL) ==
                               __builtin_parityl(ofstb & 0x2040UL) &&
                           __builtin_parityl(ofsta & 0x44000UL) ==
                               __builtin_parityl(ofstb & 0x44000UL) &&
                           __builtin_parityl(ofsta & 0x88000UL) ==
                               __builtin_parityl(ofstb & 0x88000UL) &&
                           __builtin_parityl(ofsta & 0x110000UL) ==
                               __builtin_parityl(ofstb & 0x110000UL) &&
                           __builtin_parityl(ofsta & 0x220000UL) ==
                               __builtin_parityl(ofstb & 0x220000UL));
}

bool Analyzer4K::check_conflict(void *a, void *b, bool should_conflict) {
  for (int i = 0; i < 24; ++i)
    if ((check_time((volatile char *)a, (volatile char *)b) > 410) == should_conflict)
      return true;
  return false;
}

bool Analyzer4K::check_bank_offset(void *base) {
  void *a;

  for (uint64_t i = 0; i < (4UL << num_ranks); ++i) {
    a = (void *)((char *)base + i * 0x2000UL);

    for (uint64_t j = 0; j < (64UL << num_ranks); ++j) {
      if (i == j) continue;

      if (!check_conflict(a, (void *)((char *)base + j * 0x2000UL),
                          should_conflict(i * 0x2000UL, j * 0x2000UL)))
        return false;
    }
  }

  return true;
}

void *Analyzer4K::bank_offset(void *huge_ptr) {
  for (int i = 0; i < 1024; ++i) {
    // 128 because 1 ranked modules allow us to detect pages of order at most 7
    for (uint64_t j = 0; j < (128UL << num_ranks); ++j) {
      if (check_bank_offset((void *)((char *)huge_ptr + j * 0x1000UL)))
        return (void *)(j * 0x1000UL);
    }
  }

  // not optimal IMPLEMENT ERROR HANDLING
  return nullptr;
}