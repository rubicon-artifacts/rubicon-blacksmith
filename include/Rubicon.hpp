/*
 * Copyright (c) 2025 by ETH Zurich.
 * Licensed under the GNU GPLv3 License, see LICENSE file for more details.
 */

#ifndef RUBICON_HPP
#define RUBICON_HPP

#include "Memory/Memory.hpp"
#include <cstdint>

class Rubicon {
  bool use_hugepage;
  uint64_t alignment;

  std::mt19937 gen;
  Range<uint64_t> range;

  int fd_spray;
  void *file_ptr;

public:
  /**
   * @brief Constructs a new Rubicon object used to bridge Blacksmith and Omen
   *
   * @param use_page true if memory backed by 4K pages false otherwise
   * @param use_hugepage true if memory backed by THPs false otherwise
   */
  Rubicon(bool use_page, bool use_hugepage);

  /**
   * @brief Initializes a memory page with pseudo-random values.
   *
   * @param address A virtual address used to derive the page location and seed.
   * @param constant An integer used to obfuscate the address and seed the RNG.
   */
  void restore_page(int *page_ptr);

  /**
   * @brief Performs comprehensive template testing described in the project
   * report. Checks bitflip reliability on an approximative testing data pattern
   * under various conditions.
   */
  bool check_repeatability(CodeJitter &code_jitter,
                           FuzzingParameterSet &fuzzing_params,
                           const std::vector<volatile char *> &random_rows,
                           int wait_until_hammering_us,
                           uint64_t bitflip_address64, uint64_t bitflip_mask64,
                           uint64_t bitflip_corrupted64);

  void open_spraying_file(void *file_target);
  void close_spraying_file();
  int spray_tables();
  void unspray_tables();

  void huge_split(void *sacrificial_page);
  int block_merge(void *target, unsigned order);
  int migratetype_escalation(std::vector<void *> &bait_pages);

  /**
   * @brief An interface function between Blacksmith and Rubicon
   * implementing the end-to-end attack.
   */
  void e2e(CodeJitter &code_jitter, FuzzingParameterSet &fuzzing_params,
           const std::vector<volatile char *> &aggressors,
           const std::vector<volatile char *> &random_rows,
           int wait_until_hammering_us, std::vector<BitFlip> &bit_flips);
};
#endif // RUBICON_HPP