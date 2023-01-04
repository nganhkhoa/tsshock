import ctypes
import os
import numpy as np
import time

import sys

from cuda import cuda, nvrtc, cudart

# import cuda
# print(dir(cuda))

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
    max_r = 2**60,
    threads = 4,
    blocks = 64,
    kernel_batch_size = 8
):
    # Init
    err, = cuda.cuInit(0); CHK(err)

    # Device
    err, cuDevice = cuda.cuDeviceGet(0); CHK(err)

    err, name = cuda.cuDeviceGetName(128, cuDevice); CHK(err)
    print(f"Cuda device: {name.strip()}")

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
            #b'-Xptxas=-suppress-stack-size-warning',
            '--include-path={}'.format("/usr/local/cuda/include").encode('UTF-8'),
            b'--std=c++11', b'-default-device'
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
    NUM_THREADS = threads

    # err, numBlocksPerSm = cuda.cuOccupancyMaxActiveBlocksPerMultiprocessor(kernel, NUM_THREADS, 0); CHK(err)
    # print(f"numBlocksPerSm={numBlocksPerSm}")

    NUM_BLOCKS = blocks #props.multiProcessorCount

    step = NUM_BLOCKS*NUM_THREADS*kernel_batch_size
    time_start = time.time()

    if len(sys.argv) == 1:
        print("no argument passed, default to using 1 kernel")
        print("./program <nkernels:int>")
        nkernels = 1
    else:
        nkernels = int(sys.argv[1])
    streams = [cuda.cuStreamCreate(1)[1] for i in range(nkernels)]

    t = time.localtime()
    current_time = time.strftime("%H:%M:%S", t)
    print("start time:", current_time)

    for range_start in range(0,max_r,step * nkernels):
        outputs = []
        mems = []
        for i, stream in enumerate(streams):
            base = range_start + i*step
            print(f"Starting kernel from {base} with stream: {stream.getPtr()}")

            err, d_output = cuda.cuMemAllocAsync(8, stream); CHK(err)
            err, d_houtput = cuda.cuMemAllocAsync(32, stream); CHK(err)
            err, d_p_buf = cuda.cuMemAllocAsync(len(p_buf), stream); CHK(err)
            err, d_q_buf = cuda.cuMemAllocAsync(len(q_buf), stream); CHK(err)
            err, d_p_inv_buf = cuda.cuMemAllocAsync(len(p_inv_buf), stream); CHK(err)

            mems += [
                d_output, d_houtput, d_p_buf, d_q_buf, d_p_inv_buf
            ]
            outputs += [(d_output, d_houtput)]

            err, = cuda.cuMemcpyHtoDAsync(d_p_buf, p_buf, len(p_buf), stream); CHK(err)
            err, = cuda.cuMemcpyHtoDAsync(d_q_buf, q_buf, len(q_buf), stream); CHK(err)
            err, = cuda.cuMemcpyHtoDAsync(d_p_inv_buf, p_inv_buf, len(p_inv_buf), stream); CHK(err)

            arg_values = (d_output, d_houtput,
                          len(p_buf), d_p_buf,
                          len(q_buf), d_q_buf,
                          len(p_inv_buf), d_p_inv_buf,
                          base,
                          kernel_batch_size,
                          )
            arg_types =  (None,     None,
                          ctypes.c_size_t, None,
                          ctypes.c_size_t, None,
                          ctypes.c_size_t, None,
                          ctypes.c_uint64,
                          ctypes.c_uint64,
                          )

            err, = cuda.cuLaunchKernel(kernel,
                                    NUM_BLOCKS, 1, 1,           # grid dim
                                    NUM_THREADS, 1, 1,          # block dim
                                    0, stream,                  # shared mem and stream
                                    (arg_values, arg_types), 0) # arguments
            CHK(err)

        print("waiting...")

        found = False
        enqueue = streams
        while len(enqueue) != 0 and not found:
            new_queue = []
            for i, stream in enumerate(enqueue):
                status, = cuda.cuStreamQuery(stream)
                if status == cuda.CUresult.CUDA_SUCCESS:
                    print(f"stream {stream.getPtr()} complete")
                    output_data = np.zeros(1, dtype=np.uint64)
                    err, = cuda.cuMemcpyDtoHAsync(output_data, d_output, 8, stream); CHK(err)
                    houtput_data = np.zeros(32, dtype=np.uint8)
                    err, = cuda.cuMemcpyDtoHAsync(houtput_data, d_houtput, 32, stream); CHK(err)

                    err, = cuda.cuStreamSynchronize(stream)
                    CHK(err)

                    if output_data.any():
                        idx = np.argwhere(output_data != 0)[0][0]
                        ret = int(str(output_data[idx]))
                        print("Found! ", ret, bytes(houtput_data).hex())
                        found = True
                else:
                    new_queue += [stream]
            enqueue = new_queue
            if found:
                break
            time.sleep(2)

        if found:
            for stream in enqueue:
                err, = cuda.cuStreamDestroy(stream); CHK(err)

        # cudart.cudaDeviceSynchronize()
        # found_values = []
        # for ((d_output, houtput), stream) in zip(outputs, streams):
        #     output_data = np.zeros(1, dtype=np.uint64)
        #     err, = cuda.cuMemcpyDtoHAsync(output_data, d_output, 8, stream); CHK(err)

        #     houtput_data = np.zeros(32, dtype=np.uint8)
        #     err, = cuda.cuMemcpyDtoHAsync(houtput_data, d_houtput, 32, stream); CHK(err)

        #     found_values += [output_data]

        # cudart.cudaDeviceSynchronize()

        # found = False
        # for output_data in found_values:
        #     print(output_data)
        #     if output_data.any():
        #         idx = np.argwhere(output_data != 0)[0][0]
        #         ret = int(str(output_data[idx]))
        #         print("Found! ", ret, [hex(x) for x in houtput_data])
        #         found = True

        for mem in mems:
            err, = cuda.cuMemFree(mem); CHK(err)

        if found:
            break

    for stream in streams:
        err, = cuda.cuStreamDestroy(stream);

    t = time.localtime()
    current_time = time.strftime("%H:%M:%S", t)
    print("end time:", current_time)

    err, = cuda.cuModuleUnload(module)
    err, = cuda.cuCtxDestroy(context)
    return ret

if __name__=="__main__":
    main()
