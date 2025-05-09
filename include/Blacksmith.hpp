/*
 * Copyright (c) 2025 by ETH Zurich.
 * Licensed under the GNU GPLv3 License, see LICENSE file for more details.
 */

#ifndef BLACKSMITH_INCLUDE_BLACKSMITH_HPP_
#define BLACKSMITH_INCLUDE_BLACKSMITH_HPP_

#include <string>
#include <unordered_set>
#include <GlobalDefines.hpp>

// defines the program's arguments and their default values
struct ProgramArguments {
  // the duration of the fuzzing run in second
  unsigned long runtime_limit = 120;
  // the number of ranks of the DIMM to hammer
  int num_ranks = 0;
  // no. of activations we can do within a refresh interval
  size_t acts_per_ref = 0;
  // path to JSON file to load
  std::string load_json_filename;
  // the IDs of the patterns to be loaded from a given JSON file
  std::unordered_set<std::string> pattern_ids{};
  // total number of mappings (i.e., Aggressor ID -> DRAM rows mapping) to try for a pattern
  size_t num_address_mappings_per_pattern = 3;
  // number of DRAM locations we use to check a (pattern, address mapping)'s effectiveness
  size_t num_dram_locations_per_mapping = 3;
  // whether to sweep the 'best pattern' that was found during fuzzing afterward over a contiguous chunk of memory
  bool sweeping = false;
  // the ID of the DIMM that is currently inserted
  long dimm_id = -1;
  // these two parameters define the default program mode: do fuzzing and synchronize with REFRESH
  bool do_fuzzing = true;
  // true: allocate memory using huge pages false: using super pages
  bool use_hugepage = false;
  //
  bool use_page = false;
  //
  bool nonconsec = false;
  //
  bool set_priority = true;
  //
  bool e2e = false;
};

extern ProgramArguments program_args;

int main(int argc, char **argv);

void handle_args(int argc, char **argv);

#endif //BLACKSMITH_INCLUDE_BLACKSMITH_HPP_
