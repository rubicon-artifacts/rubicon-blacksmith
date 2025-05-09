#include "Blacksmith.hpp"

#include <sys/resource.h>

#include "Forges/FuzzyHammerer.hpp"

#include <argagg/argagg.hpp>
#include <argagg/convert/csv.hpp>

ProgramArguments program_args;

int main(int argc, char **argv) {
  Logger::initialize();

  handle_args(argc, argv);

  // prints the current git commit and some program metadata
  Logger::log_metadata(GIT_COMMIT_HASH, program_args.runtime_limit);

  // give this process the highest CPU priority so it can hammer with less
  // interruptions
  if (program_args.set_priority) {
    int ret = setpriority(PRIO_PROCESS, 0, -20);
    if (ret != 0)
      Logger::log_error("Instruction setpriority failed.");
  }

  Logger::log_info(
      format_string("Timestamp (Started Attack):  %lu.", realtime_now()));

  // allocate a large bulk of contiguous memory
  Memory memory(program_args.use_hugepage, program_args.use_page,
                program_args.num_ranks);
  memory.allocate_memory(MEM_SIZE);

  // find address sets that create bank conflicts
  DramAnalyzer dram_analyzer(memory.get_starting_address());
  dram_analyzer.find_bank_conflicts();
  if (program_args.num_ranks != 0) {
    dram_analyzer.load_known_functions(program_args.num_ranks);
  } else {
    Logger::log_error("Program argument '--ranks <integer>' was probably not "
                      "passed. Cannot continue.");
    exit(EXIT_FAILURE);
  }
  // initialize the DRAMAddr class to load the proper memory configuration
  DRAMAddr::initialize(dram_analyzer.get_bank_rank_functions().size(),
                       memory.get_starting_address());

  // count the number of possible activations per refresh interval, if not given
  // as program argument
  if (program_args.acts_per_ref == 0)
    program_args.acts_per_ref = dram_analyzer.count_acts_per_ref();

  if (!program_args.load_json_filename.empty()) {
    ReplayingHammerer replayer(memory, program_args.nonconsec);
    if (program_args.sweeping) {
      replayer.replay_patterns_brief(program_args.load_json_filename,
                                     program_args.pattern_ids, MB(256), false,
                                     program_args.e2e);
    } else {
      replayer.replay_patterns(program_args.load_json_filename,
                               program_args.pattern_ids, program_args.e2e);
    }
  } else if (program_args.do_fuzzing) {
    FuzzyHammerer::n_sided_frequency_based_hammering(
        dram_analyzer, memory, static_cast<int>(program_args.acts_per_ref),
        program_args.runtime_limit,
        program_args.num_address_mappings_per_pattern, program_args.sweeping,
        program_args.nonconsec, program_args.e2e);
  } else {
    Logger::log_error(
        "Invalid combination of program control-flow arguments given. "
        "Note: Fuzzing is only supported with synchronized hammering.");
  }

  Logger::close();
  return EXIT_SUCCESS;
}

void handle_args(int argc, char **argv) {
  // An option is specified by four things:
  //    (1) the name of the option,
  //    (2) the strings that activate the option (flags),
  //    (3) the option's help message,
  //    (4) and the number of arguments the option expects.
  argagg::parser argparser{{
      {"help", {"-h", "--help"}, "shows this help message", 0},
      {"dimm-id",
       {"-d", "--dimm-id"},
       "internal identifier of the currently inserted DIMM (default: 0)",
       1},
      {"ranks",
       {"-r", "--ranks"},
       "number of ranks on the DIMM, used to determine bank/rank/row "
       "functions, assumes Intel Coffe Lake CPU (default: None)",
       1},

      {"fuzzing",
       {"-f", "--fuzzing"},
       "perform a fuzzing run (default program mode)",
       0},
      {"replay-patterns",
       {"-y", "--replay-patterns"},
       "replays patterns given as comma-separated list of pattern IDs",
       1},

      {"load-json",
       {"-j", "--load-json"},
       "loads the specified JSON file generated in a previous fuzzer run, "
       "loads patterns given by --replay-patterns or determines the best ones",
       1},

      // note that these seven parameters don't require a value, their presence
      // already equals a "true"
      {"sweeping",
       {"-w", "--sweeping"},
       "sweep the best pattern over a contig. memory area after fuzzing "
       "(default: absent)",
       0},
      {"nonconsec", {"-n", "--nonconsec"}, "sweep nonconsecutively", 0},
      {"hugepage", {"-u", "--hugepage"}, "allocate memory using huge pages", 0},
      {"page", {"-q", "--page"}, "allocate memory using regular pages", 0},
      {"skip-priority",
       {"-k", "--skip-priority"},
       "skips setting high process priority",
       0},
      {"e2e", {"-e", "--e2e"}, "executes the end to end attack", 0},

      {"runtime-limit",
       {"-t", "--runtime-limit"},
       "number of seconds to run the fuzzer before sweeping/terminating "
       "(default: 120)",
       1},
      {"acts-per-ref",
       {"-a", "--acts-per-ref"},
       "number of activations in a tREF interval, i.e., 7.8us (default: None)",
       1},
      {"probes",
       {"-p", "--probes"},
       "number of different DRAM locations to try each pattern on (default: "
       "NUM_BANKS/4)",
       1},
  }};

  argagg::parser_results parsed_args;
  try {
    parsed_args = argparser.parse(argc, argv);
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    exit(EXIT_FAILURE);
  }

  if (parsed_args["help"]) {
    std::cerr << argparser;
    exit(EXIT_SUCCESS);
  }

  /**
   * mandatory parameters
   */
  if (parsed_args.has_option("dimm-id")) {
    program_args.dimm_id = parsed_args["dimm-id"].as<int>(0);
    Logger::log_debug(
        format_string("Set --dimm-id: %ld", program_args.dimm_id));
  } else {
    Logger::log_error("Program argument '--dimm-id <integer>' is mandatory! "
                      "Cannot continue.");
    exit(EXIT_FAILURE);
  }

  if (parsed_args.has_option("ranks")) {
    program_args.num_ranks = parsed_args["ranks"].as<int>(0);
    Logger::log_debug(format_string("Set --ranks=%d", program_args.num_ranks));
  } else {
    Logger::log_error(
        "Program argument '--ranks <integer>' is mandatory! Cannot continue.");
    exit(EXIT_FAILURE);
  }

  /**
   * optional parameters
   */
  program_args.sweeping =
      parsed_args.has_option("sweeping") || program_args.sweeping;
  Logger::log_debug(format_string("Set --sweeping=%s",
                                  (program_args.sweeping ? "true" : "false")));

  program_args.runtime_limit = parsed_args["runtime-limit"].as<unsigned long>(
      program_args.runtime_limit);
  Logger::log_debug(
      format_string("Set --runtime_limit=%ld", program_args.runtime_limit));

  program_args.acts_per_ref =
      parsed_args["acts-per-ref"].as<size_t>(program_args.acts_per_ref);
  Logger::log_debug(
      format_string("Set --acts-per-ref=%d", program_args.acts_per_ref));

  program_args.num_address_mappings_per_pattern =
      parsed_args["probes"].as<size_t>(
          program_args.num_address_mappings_per_pattern);
  Logger::log_debug(format_string(
      "Set --probes=%d", program_args.num_address_mappings_per_pattern));

  program_args.use_hugepage = parsed_args.has_option("hugepage");
  Logger::log_debug(format_string(
      "Set --hugepage=%s", (program_args.use_hugepage ? "true" : "false")));

  program_args.nonconsec = parsed_args.has_option("nonconsec");
  Logger::log_debug(format_string("Set --nonconsec=%s",
                                  (program_args.nonconsec ? "true" : "false")));

  program_args.set_priority = !parsed_args.has_option("skip-priority");
  Logger::log_debug(format_string(
      "Set --priority=%s", (program_args.set_priority ? "true" : "false")));

  program_args.e2e = parsed_args.has_option("e2e");
  Logger::log_debug(
      format_string("Set --e2e=%s", (program_args.e2e ? "true" : "false")));

  program_args.use_page = parsed_args.has_option("page");
  Logger::log_debug(format_string("Set --page=%s",
                                  (program_args.use_page ? "true" : "false")));

  if (program_args.use_hugepage && program_args.use_page) {
    Logger::log_error("Program arguments --hugepage, --page are mutually "
                      "exclusive! Cannot continue.");
    exit(EXIT_FAILURE);
  }

  /**
   * program modes
   */
  if (parsed_args.has_option("load-json")) {
    program_args.load_json_filename =
        parsed_args["load-json"].as<std::string>("");
    if (parsed_args.has_option("replay-patterns")) {
      auto vec_pattern_ids =
          parsed_args["replay-patterns"].as<argagg::csv<std::string>>();
      program_args.pattern_ids = std::unordered_set(
          vec_pattern_ids.values.begin(), vec_pattern_ids.values.end());
    } else {
      program_args.pattern_ids = std::unordered_set<std::string>();
    }
  } else {
    program_args.do_fuzzing = parsed_args["fuzzing"].as<bool>(true);
  }
}
