import ctypes
import os
import numpy as np
import time

import sys

from cuda import cuda, nvrtc, cudart


class SearchInstance:
    def __init__(self, kernel, stream, kernel_batch_size, nblocks, nthreads, step):
        self.kernel = kernel
        self.stream = stream
        self.kernel_batch_size = kernel_batch_size
        self.nblocks = nblocks
        self.nthreads = nthreads
        self.step = step

    def destroy(self):
        err, = cuda.cuStreamDestroy(self.stream);
        for mem in self.mems:
            err, = cuda.cuMemFree(mem); CHK(err)

    def set_args(self, p_buf, q_buf, p_inv_buf):
        self.p_buf = p_buf
        self.q_buf = q_buf
        self.p_inv_buf = p_inv_buf

    def report_time(self):
        end = time.time()
        elapsed = end - self.start_time
        ops_per_sec = self.kernel_batch_size / elapsed
        print(f"kernel search from [{self.start}] time elapsed {elapsed}s with {ops_per_sec} op/s")

    def search_next(self):
        print(f"kernel search from [{self.start}] completed; continue search from {self.start + self.step}")
        self.search(self.start + self.step)

    def result(self):
        stream = self.stream
        d_output, d_houtput = self.outputs

        output_data = np.zeros(1, dtype=np.uint64)
        err, = cuda.cuMemcpyDtoHAsync(output_data, d_output, 8, stream); CHK(err)
        houtput_data = np.zeros(32, dtype=np.uint8)
        err, = cuda.cuMemcpyDtoHAsync(houtput_data, d_houtput, 32, stream); CHK(err)

        err, = cuda.cuStreamSynchronize(stream)
        CHK(err)

        if output_data.any():
            idx = np.argwhere(output_data != 0)[0][0]
            ret = int(str(output_data[idx]))
            return ret
        return None

    def completed(self):
        status, = cuda.cuStreamQuery(self.stream)
        return status == cuda.CUresult.CUDA_SUCCESS

    def search(self, start):
        stream = self.stream
        kernel = self.kernel
        kernel_batch_size = self.kernel_batch_size

        p_buf = self.p_buf
        q_buf = self.q_buf
        p_inv_buf = self.p_inv_buf

        self.start = start
        self.start_time = time.time()
        print(f"searching from {start}")

        if not hasattr(self, "mems"):
            err, d_output = cuda.cuMemAllocAsync(8, stream); CHK(err)
            err, d_houtput = cuda.cuMemAllocAsync(32, stream); CHK(err)
            err, d_p_buf = cuda.cuMemAllocAsync(len(p_buf), stream); CHK(err)
            err, d_q_buf = cuda.cuMemAllocAsync(len(q_buf), stream); CHK(err)
            err, d_p_inv_buf = cuda.cuMemAllocAsync(len(p_inv_buf), stream); CHK(err)

            err, = cuda.cuMemcpyHtoDAsync(d_p_buf, p_buf, len(p_buf), stream); CHK(err)
            err, = cuda.cuMemcpyHtoDAsync(d_q_buf, q_buf, len(q_buf), stream); CHK(err)
            err, = cuda.cuMemcpyHtoDAsync(d_p_inv_buf, p_inv_buf, len(p_inv_buf), stream); CHK(err)

            self.mems = [
                d_output, d_houtput, d_p_buf, d_q_buf, d_p_inv_buf
            ]
        else:
            d_output, d_houtput, d_p_buf, d_q_buf, d_p_inv_buf = self.mems

        self.outputs = (d_output, d_houtput)

        arg_values = (d_output, d_houtput,
                      len(p_buf), d_p_buf,
                      len(q_buf), d_q_buf,
                      len(p_inv_buf), d_p_inv_buf,
                      start,
                      kernel_batch_size,
                      )
        arg_types =  (None,     None,
                      ctypes.c_size_t, None,
                      ctypes.c_size_t, None,
                      ctypes.c_size_t, None,
                      ctypes.c_uint64,
                      ctypes.c_uint64,
                      )

        nblocks = self.nblocks
        nthreads = self.nthreads
        err, = cuda.cuLaunchKernel(kernel,
                                nblocks, 1, 1,           # grid dim
                                nthreads, 1, 1,          # block dim
                                0, stream,                  # shared mem and stream
                                (arg_values, arg_types), 0) # arguments
        CHK(err)

def CHK(err):
    if isinstance(err, cuda.CUresult):
        if err != cuda.CUresult.CUDA_SUCCESS:
            raise RuntimeError('Cuda Error: {}'.format(err))
    elif isinstance(err, nvrtc.nvrtcResult):
        if err != nvrtc.nvrtcResult.NVRTC_SUCCESS:
            raise RuntimeError('Nvrtc Error: {}'.format(err))
    elif isinstance(err, cudart.cudaError_t):
        if err != cudart.cudaError_t.cudaSuccess:
            raise RuntimeError('Cudart Error: {}'.format(err))
    else:
        raise RuntimeError('Unknown error type: {}'.format(err))

def work(
    p_buf,
    q_buf,
    p_inv_buf,
    args,
    max_r = 2**60,
):
    # Init
    err, = cuda.cuInit(0); CHK(err)

    # Device
    err, cuDevice = cuda.cuDeviceGet(0); CHK(err)

    err, name = cuda.cuDeviceGetName(128, cuDevice); CHK(err)
    name = name.replace(b'\x00', b'')
    name = name.rstrip()
    print(f"Cuda device: {name}")

    err, props = cudart.cudaGetDeviceProperties(cuDevice); CHK(err)
    for k in ['maxThreadsPerBlock', 'maxThreadsDim', 'maxGridSize', 'multiProcessorCount', 'major', 'minor', 'concurrentKernels']:
        print(f"{k}: {getattr(props, k)}")

    # Ctx
    err, context = cuda.cuCtxCreate(0, cuDevice); CHK(err)

    # Create program
    with open('brute.cu') as f:
        source = f.read()
    err, prog = nvrtc.nvrtcCreateProgram(str.encode(source), b'brute.cu', 0, [], []); CHK(err)

    # Get target architecture
    err, major = cuda.cuDeviceGetAttribute(cuda.CUdevice_attribute.CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR, cuDevice); CHK(err)
    err, minor = cuda.cuDeviceGetAttribute(cuda.CUdevice_attribute.CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR, cuDevice); CHK(err)
    err, nvrtc_major, nvrtc_minor = nvrtc.nvrtcVersion(); CHK(err)

    if True or not os.path.exists('brute.cu.bin'):
        use_cubin = (nvrtc_minor >= 1)
        prefix = 'sm' if use_cubin else 'compute'
        arch_arg = bytes(f'--gpu-architecture={prefix}_{major}{minor}', 'ascii')

        # Compile program
        opts = [
            b'--fmad=false', arch_arg, b'--device-int128',
            b'-Xptxas=-suppress-stack-size-warning',
            '--include-path={}'.format("/usr/local/cuda/include").encode('UTF-8'),
            b'--std=c++11',
            b'-default-device',
            b'--ptxas-options=-v',
        ]
        print("Compiling... may take a while...")
        comperr, = nvrtc.nvrtcCompileProgram(prog, len(opts), opts)
        print("Compiled.")

        # Get log from compilation
        err, logSize = nvrtc.nvrtcGetProgramLogSize(prog); CHK(err)
        log = b' ' * logSize
        err, = nvrtc.nvrtcGetProgramLog(prog, log); CHK(err)
        print(log.decode()); CHK(comperr)

        # Get data from compilation
        if use_cubin:
            err, dataSize = nvrtc.nvrtcGetCUBINSize(prog); CHK(err)
            data = b' ' * dataSize
            err, = nvrtc.nvrtcGetCUBIN(prog, data); CHK(err)
        else:
            err, dataSize = nvrtc.nvrtcGetPTXSize(prog); CHK(err)
            data = b' ' * dataSize
            err, = nvrtc.nvrtcGetPTX(prog, data); CHK(err)

        with open('brute.cu.bin','wb') as f:
            f.write(data)
    else:
        print("Reuse compiled binary.")
        with open('brute.cu.bin','rb') as f:
            data = f.read()

    # Load data as module data and retrieve function
    data = np.char.array(data)
    err, module = cuda.cuModuleLoadData(data); CHK(err)
    err, kernel = cuda.cuModuleGetFunction(module, b'brute'); CHK(err)

    # Test the kernel

    # err, numBlocksPerSm = cuda.cuOccupancyMaxActiveBlocksPerMultiprocessor(kernel, NUM_THREADS, 0); CHK(err)
    # print(f"numBlocksPerSm={numBlocksPerSm}")

    NUM_THREADS = args.threads
    NUM_BLOCKS = args.blocks
    kernel_batch_size = args.batch

    step = NUM_BLOCKS*NUM_THREADS*kernel_batch_size
    time_start = time.time()

    nkernels = args.kernels

    kernel_args = {
        "kernel batch size": kernel_batch_size,
        "nblocks": NUM_BLOCKS,
        "nthreads": NUM_THREADS,
        "step": step,
    }
    print("launching kernels with:")
    for k, v in kernel_args.items():
        print(">>", k, v)

    streams = [cuda.cuStreamCreate(1)[1] for i in range(nkernels)]
    streams = [
        SearchInstance(kernel, s, kernel_batch_size, NUM_BLOCKS, NUM_THREADS, step * nkernels) for s in streams
    ]
    list(map(lambda s: s.set_args(p_buf, q_buf, p_inv_buf), streams))

    # first iteration
    for i, stream in enumerate(streams):
        base = i*step
        stream.search(base)

    print("waiting...")

    start_time = time.time()
    print("started on:", time.asctime(time.localtime()))
    while True:
        completed = list(filter(lambda s: s.completed(), streams))
        if len(completed) == 0:
            time.sleep(2)
            continue
        results = map(lambda s: (s, s.result()), completed)
        for s, result in results:
            if result is not None:
                s.report_time()
                found = result
                break
        else:
            for stream in completed:
                stream.report_time()
                stream.search_next()
            continue
        break
    end_time = time.time()
    elapsed = end_time - start_time
    elapsed_min = elapsed / 60
    print(f"searched time {elapsed}s ({elapsed_min}m)")

    for stream in streams:
        stream.destroy()

    err, = cuda.cuModuleUnload(module)
    err, = cuda.cuCtxDestroy(context)
    return found

if __name__=="__main__":
    main()
