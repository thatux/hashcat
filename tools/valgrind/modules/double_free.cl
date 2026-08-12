/* Ground-truth fixture: exactly one bug.
 *
 * Kept under the name "double_free" per the original request, but OpenCL C
 * kernels don't call free() on-device the way host C does -- there is no
 * on-device analogue of a double free.
 *
 * The first candidate for "closest real equivalent" was an out-of-bounds
 * __global buffer write. That was tried and abandoned: under PoCL's
 * pthread CPU driver in this environment, small-buffer OOB writes proved
 * empirically unreliable to detect deterministically -- a modest overrun
 * was silently absorbed by the allocator's padding, a large one corrupted
 * Valgrind's own heap bookkeeping outright, and the narrow band in between
 * was flaky across repeated runs (sometimes caught, sometimes not, and
 * sometimes the run hung outright). None of that is a fit for a ground-
 * truth self-test, which needs to be exact and reproducible every time.
 *
 * What *is* exact and reproducible (verified across repeated clean-cache
 * runs): a private variable read before it's ever written, used in a
 * branch. This is a real, common OpenCL bug class (e.g. an uninitialised
 * accumulator or loop-bound variable) and Memcheck's uninitialised-value
 * tracking catches it deterministically even through PoCL's CPU JIT path.
 */

__kernel void bad_write(__global int *buf)
{
    int uninitialised_value;
    size_t i = get_global_id(0);

    if (uninitialised_value == 42)
    {
        buf[i] = 1;
    }
    else
    {
        buf[i] = 0;
    }
}
