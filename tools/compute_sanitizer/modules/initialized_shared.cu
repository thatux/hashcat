/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <cuda_runtime.h>
#include <stdint.h>

typedef uint32_t u32;

// This control initializes every value before another thread reads it.
__global__ void initialized_shared_kernel (u32 *out)
{
  __shared__ volatile u32 values[32];

  values[threadIdx.x] = threadIdx.x;

  __syncthreads ();

  out[threadIdx.x] = values[(threadIdx.x + 1) & 31];
}

int main ()
{
  u32 *out = NULL;

  if (cudaMalloc (&out, 32 * sizeof (u32)) != cudaSuccess) return 1;

  initialized_shared_kernel<<<1, 32>>> (out);

  const cudaError_t rc = cudaDeviceSynchronize ();
  const cudaError_t free_rc = cudaFree (out);

  if (rc != cudaSuccess) return 1;
  if (free_rc != cudaSuccess) return 1;

  return 0;
}
