/*
 * Copyright (c) 2025 by ETH Zurich.
 * Licensed under the GNU GPLv3 License, see LICENSE file for more details.
 */

#include "Memory/Memory.hpp"

/**
 * @brief Small library for detecting edges of contiguous memory blocks obtained by exhausting buddy
 * 
 */
class Analyzer4K {
public:

int num_ranks;

Analyzer4K(int num_ranks);

/**
 * @brief measures the average number of cycles required to complete two consecutive memory accesses to a1 and a2
 * 
 * @param a1 pointer to the first page
 * @param a2 pointer to the second page
 * @return int average number of cycles
 */
int inline check_time(volatile char *a1, volatile char *a2);

/**
 * @brief checks whether two consecutive memory accesses to ofsta and ofstb
 * should result in a bank conflict according to the bank/rank functions
 * 
 * TODO: This is set up for one ranked DIMMs only and needs to be updated to handle both cases
 *
 * @param ofsta pointer to the first page
 * @param ofstb pointer to the second page
 */
bool should_conflict(uint64_t ofsta, uint64_t ofstb);

/**
 * @brief checks whether bank conflicts happen between address pairs predicted by the bank/rank functions
 * 
 * @param a pointer to the first page
 * @param b pointer to the second page
 * @param should_conflict true if bank conflict expected false otherwise
 */
bool check_conflict(void *a, void *b, bool should_conflict);

/**
 * @brief checks whether base points to the edge of a large compound page by observing the bank conflict pattern
 * 
 * @param base pointer to the start of the potential block
 */
bool check_bank_offset(void *base);

/**
 * @brief detects the edge of a contiguous memory block backing memory at huge_ptr
 * 
 * @return void* offset such that return + huge_ptr points to the next edge after huge_ptr
 */
void *bank_offset(void *huge_ptr);

};