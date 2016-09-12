/*
 * Argon2 source code package
 *
 * Written by Daniel Dinu and Dmitry Khovratovich, 2015
 *
 * This work is licensed under a Creative Commons CC0 1.0 License/Waiver.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along
 * with
 * this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#ifndef ARGON2_REF_H
#define ARGON2_REF_H

#include "core.h"

/*
 * Function fills a new memory block and optionally XORs the old block over the new one.
 * @next_block must be initialized.
 * @param prev_block Pointer to the previous block
 * @param ref_block Pointer to the reference block
 * @param next_block Pointer to the block to be constructed
 * @param with_xor Whether to XOR into the new block (1) or just overwrite (0)
 * @pre all block pointers must be valid
 */
void fill_block(const block *prev_block, const block *ref_block,
                block *next_block, int with_xor);

#endif /* ARGON2_REF_H */
