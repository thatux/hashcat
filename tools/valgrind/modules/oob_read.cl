/* Ground-truth fixture: exactly one bug, the read-side counterpart of
 * double_free.cl. See double_free.cl for why this is an uninitialised-value
 * bug rather than the originally-attempted out-of-bounds buffer access:
 * OOB access on small PoCL-pthread-allocated buffers proved empirically
 * unreliable to detect deterministically in this environment (confirmed
 * flaky across repeated clean-cache runs -- sometimes caught, sometimes
 * missed entirely), whereas an uninitialised private variable is caught
 * every time.
 *
 * This one differs in shape from double_free.cl: the uninitialised value
 * is used to compute an array index rather than a branch condition.
 */

__kernel void bad_read(__global int *buf, __global int *out)
{
    int uninitialised_index;
    size_t i = get_global_id(0);

    out[i] = buf[uninitialised_index % 16];
}
