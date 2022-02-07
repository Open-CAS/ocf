#include "utils_generator.h"

/**
 * @brief Reverse bits of 32-bit value
 *
 * @param[in] x Value to be reversed
 *
 * @return Reversed value
 */
static inline uint32_t bitreverse32(register uint32_t x)
{
	x = (((x & 0xaaaaaaaa) >> 1) | ((x & 0x55555555) << 1));
	x = (((x & 0xcccccccc) >> 2) | ((x & 0x33333333) << 2));
	x = (((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4));
	x = (((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8));
	return((x >> 16) | (x << 16));
}

/**
 * @brief Initialize bisect generator state
 *
 * @param[in] generator Pointer to generator structure
 * @param[in] limit Limit of the value returned by generator (maximum value
 *            returned by the generator is limit - 1)
 * @param[in] offset Offset at which generator should start
 *
 * @return Reversed value
 */
void ocf_generator_bisect_init(
		struct ocf_generator_bisect_state *generator,
		uint32_t limit, uint32_t offset)
{
	unsigned clz;
	uint32_t maplen;

	clz = __builtin_clz(limit - 1);
	maplen = 1 << (32 - clz);

	generator->curr = (uint64_t)offset * maplen / limit;
	generator->limit = limit;
}

/**
 * @brief Generate next value of bisect generator
 *
 * This function calculates next value of the generator. The generator
 * pattern is based on order of indexes in array visited with bisection
 * algorithm, where always the left child is visited first at every depth.
 * This can be imagined as a special implementation of BFS done on a full
 * binary tree, where visiting nodes on each depth level is done the same
 * order as original array (so the algorithm is recursive at each level).
 *
 * Example:
 *
 * 1. We generate array of all values for number of bits needed to express
 *    limit value - 1.
 *
 * For limit==14 (4 bits) it would be:
 * [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
 *
 * 2. We take first element of the array, and then build full binary tree
 *    from other elements (it should always be possible to build a full
 *    binary tree, as number of remaining elements is always 2^n-1).
 *
 * The full binary tree for example array looks like this:
 *
 * Depth 0 ->                      8
 *                               /  \
 *                              /    \
 *                             /      \
 *                            /        \
 *                           /          \
 *                          /            \
 *                         /              \
 *                        /                \
 * Depth 1 ->            4                 12
 *                     /  \               /  \
 *                    /    \             /    \
 *                   /      \           /      \
 * Depth 2 ->       2        6        10       14
 *                /  \     /  \      /  \     /  \
 * Depth 3 ->    1    3   5    7    9   11  13   15
 *
 * 3. We traverse the tree:
 *    a) If depth level has one element, we take it.
 *    b) If depth level has two elements, we take left and then right.
 *    c) If depth level has more than two elements, we repeat steps
 *       from 2 on array built from elements on that level left to right.
 *
 * At level 0 we take 8, at level 1 we take 4 and 12, and at level 3 we
 * take 2 and build tree like this one:
 *
 *    10
 *   /  \
 *  6   14
 *
 * Then at level 0 of that tree we take 10, at level 1 we take 6 and 14,
 * and then we go back the original tree.
 *
 * At level 3 we take 1 and we build another tree from remaining elements
 * of that level:
 *
 *               9
 *             /  \
 *            /    \
 *           /      \
 *          5       13
 *        /  \     /  \
 *       3    7  11   15
 *
 * Repeating step 3 on that tree we get elements 9, then 5 and 13, and then
 * by running steps from 2 on the lowest level of that tree we get elements
 * in following order: 3, 11, 7 and 15.
 *
 * So the entire sequence would be as follows:
 * [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
 *
 * This algorithm is however quite complex, and it can be simplified
 * significantly thanks to properties of the result sequence. Note that
 * when this sequence is written in binary it looks like this:
 *
 *  0 0000
 *  8 1000
 *  4 0100
 * 12 1100
 *  2 0010
 * 10 1010
 *  6 0110
 * 14 1110
 *  1 0001
 *  9 1001
 *  5 0101
 * 13 1101
 *  3 0011
 * 11 1011
 *  7 0111
 * 15 1111
 *
 * So in its binary representation it looks like a mirror image of binary
 * representation of the original sequence:
 *
 *  0 0000 0000  0
 *  8 1000 0001  1
 *  4 0100 0010  2
 * 12 1100 0011  3
 *  2 0010 0100  4
 * 10 1010 0101  5
 *  6 0110 0110  6
 * 14 1110 0111  7
 *  1 0001 1000  8
 *  9 1001 1001  9
 *  5 0101 1010 10
 * 13 1101 1011 11
 *  3 0011 1100 12
 * 11 1011 1101 13
 *  7 0111 1110 14
 * 15 1111 1111 15
 *
 * With that knowledge we can easily calculate the next result value by just
 * reversing order of bits for each value in original sequence.
 *
 * As a result we are left with sequence that contains all the numbers that
 * can be expressed with number of bits reqiured to express limit - 1. The only
 * thing we need to do at that point is to just filter out values that do not
 * fit within the limit.
 *
 * @param[in] generator Pointer to generator structure
 *
 * @return Generated value
 */
uint32_t ocf_generator_bisect_next(
		struct ocf_generator_bisect_state *generator)
{
	unsigned clz;
	uint32_t maplen;
	uint32_t value;

	clz = __builtin_clz(generator->limit - 1);
	maplen = 1 << (32 - clz);

	do {
		value = bitreverse32(generator->curr) >> clz;
		generator->curr = (generator->curr + 1) % maplen;
	} while (value >= generator->limit);

	return value;
}
