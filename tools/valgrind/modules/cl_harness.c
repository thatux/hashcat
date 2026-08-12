/* Tiny, generic (non-hashcat-specific) OpenCL host loader: builds and
 * enqueues one kernel from an arbitrary .cl file against a small buffer.
 * Used to run the .cl fixtures under Valgrind via a CPU OpenCL device
 * (PoCL) -- a bare .cl file has nothing to launch it on its own.
 *
 * Usage: cl_harness <kernel.cl> <kernel_name> [global_size]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CL/cl.h>

#define BUF_ELEMS 16

static void die(const char *msg)
{
    fprintf(stderr, "cl_harness: %s\n", msg);
    exit(1);
}

static char *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) die("cannot open kernel file");
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t) len + 1);
    if (!buf) die("out of memory");
    if (fread(buf, 1, (size_t) len, f) != (size_t) len) die("short read");
    buf[len] = '\0';
    fclose(f);
    if (out_len) *out_len = (size_t) len;
    return buf;
}

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        fprintf(stderr, "usage: %s <kernel.cl> <kernel_name> [global_size]\n", argv[0]);
        return 2;
    }

    const char *kernel_path = argv[1];
    const char *kernel_name = argv[2];
    size_t global_size = (argc >= 4) ? (size_t) strtoul(argv[3], NULL, 10) : 4;

    cl_uint num_platforms = 0;
    clGetPlatformIDs(0, NULL, &num_platforms);
    if (num_platforms == 0) die("no OpenCL platforms found");

    cl_platform_id *platforms = malloc(sizeof(cl_platform_id) * num_platforms);
    clGetPlatformIDs(num_platforms, platforms, NULL);

    cl_device_id device = NULL;
    cl_platform_id chosen_platform = NULL;

    for (cl_uint i = 0; i < num_platforms && !device; i++)
    {
        cl_uint num_devices = 0;
        if (clGetDeviceIDs(platforms[i], CL_DEVICE_TYPE_CPU, 0, NULL, &num_devices) != CL_SUCCESS || num_devices == 0)
            continue;
        cl_device_id *devices = malloc(sizeof(cl_device_id) * num_devices);
        clGetDeviceIDs(platforms[i], CL_DEVICE_TYPE_CPU, num_devices, devices, NULL);
        device = devices[0];
        chosen_platform = platforms[i];
        free(devices);
    }
    free(platforms);

    if (!device) die("no CPU OpenCL device found (is PoCL installed and POCL_DEVICES=cpu set?)");

    cl_int err;
    cl_context_properties props[] = { CL_CONTEXT_PLATFORM, (cl_context_properties) chosen_platform, 0 };
    cl_context ctx = clCreateContext(props, 1, &device, NULL, NULL, &err);
    if (err != CL_SUCCESS) die("clCreateContext failed");

    cl_command_queue queue = clCreateCommandQueue(ctx, device, 0, &err);
    if (err != CL_SUCCESS) die("clCreateCommandQueue failed");

    size_t src_len;
    char *src = read_file(kernel_path, &src_len);
    cl_program program = clCreateProgramWithSource(ctx, 1, (const char **) &src, &src_len, &err);
    if (err != CL_SUCCESS) die("clCreateProgramWithSource failed");

    err = clBuildProgram(program, 1, &device, NULL, NULL, NULL);
    if (err != CL_SUCCESS)
    {
        size_t log_size = 0;
        clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 0, NULL, &log_size);
        char *log = malloc(log_size + 1);
        clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, log_size, log, NULL);
        log[log_size] = '\0';
        fprintf(stderr, "%s\n", log);
        free(log);
        die("clBuildProgram failed");
    }

    cl_kernel kernel = clCreateKernel(program, kernel_name, &err);
    if (err != CL_SUCCESS) die("clCreateKernel failed (check kernel_name)");

    size_t buf_bytes = BUF_ELEMS * sizeof(cl_int);
    cl_mem buf = clCreateBuffer(ctx, CL_MEM_READ_WRITE, buf_bytes, NULL, &err);
    if (err != CL_SUCCESS) die("clCreateBuffer(buf) failed");
    cl_mem out = clCreateBuffer(ctx, CL_MEM_READ_WRITE, buf_bytes, NULL, &err);
    if (err != CL_SUCCESS) die("clCreateBuffer(out) failed");

    cl_int zero_data[BUF_ELEMS];
    memset(zero_data, 0, sizeof(zero_data));
    clEnqueueWriteBuffer(queue, buf, CL_TRUE, 0, buf_bytes, zero_data, 0, NULL, NULL);
    clEnqueueWriteBuffer(queue, out, CL_TRUE, 0, buf_bytes, zero_data, 0, NULL, NULL);

    clSetKernelArg(kernel, 0, sizeof(cl_mem), &buf);
    /* second argument is optional: kernels that only take one buffer just
     * make this call fail with CL_INVALID_ARG_INDEX, which we ignore */
    clSetKernelArg(kernel, 1, sizeof(cl_mem), &out);

    err = clEnqueueNDRangeKernel(queue, kernel, 1, NULL, &global_size, NULL, 0, NULL, NULL);
    if (err != CL_SUCCESS) die("clEnqueueNDRangeKernel failed");

    clFinish(queue);

    clReleaseMemObject(buf);
    clReleaseMemObject(out);
    clReleaseKernel(kernel);
    clReleaseProgram(program);
    clReleaseCommandQueue(queue);
    clReleaseContext(ctx);
    free(src);

    printf("cl_harness: kernel '%s' executed\n", kernel_name);
    return 0;
}
