#include "cuda.h"
#include "cuda_runtime.h"
#include <cstdio>

#define CUDA_SAFE_CALL(expr)				\
	{						\
		cudaError_t err = (expr);		\
		if (err != cudaSuccess)			\
		{					\
			printf("Cuda error: %s\n", cudaGetErrorString(err));	\
			exit(1);			\
		}					\
	}

int main(void)
{
  int deviceCount;
  CUDA_SAFE_CALL(cudaGetDeviceCount(&deviceCount));
  printf("There are %d devices.\n\n", deviceCount);
  int device;
  for(device = 0; device<deviceCount; device++)
  {
    cudaDeviceProp deviceProp;
    CUDA_SAFE_CALL(cudaGetDeviceProperties(&deviceProp, device));
    if(device == 0)
    {
      if(deviceProp.major == 9999 && deviceProp.minor == 9999)
        printf("There is no device supporting CUDA.\n");
      else if(deviceCount == 1)
        printf("This is 1 device supporting CUDA.\n");
      else
        printf("There are %d devices supporting CUDA.\n", deviceCount);
    }
    printf("Device %d is called %s\n", device, deviceProp.name);

    printf("\tDevice Properties:\n");
    printf("\t\tHas timeout enabled: %d\n",deviceProp.kernelExecTimeoutEnabled);
    printf("\t\tECC enabled: %d\n",deviceProp.ECCEnabled);
    printf("\t\tClock rate %ld Hz\n",long(deviceProp.clockRate)*1000);
    printf("\t\tCompute capability: %d.%d\n",deviceProp.major,deviceProp.minor);
    printf("\t\tCompute mode: %d\n",deviceProp.computeMode);
    printf("\t\tConcurrent kernels: %d\n", deviceProp.concurrentKernels);
    printf("\t\tIntegrated device: %d\n",deviceProp.integrated);
    printf("\t\tSupports unified addressing: %d\n",deviceProp.unifiedAddressing);

    printf("\tCompute Properties:\n");
    printf("\t\tNumber of SMs: %d\n",deviceProp.multiProcessorCount);
    printf("\t\tWarp size: %d threads\n",deviceProp.warpSize);
    printf("\t\tMaximum threads per CTA: %d\n",deviceProp.maxThreadsPerBlock);
    printf("\t\tMaximum threads per SM: %d\n",deviceProp.maxThreadsPerMultiProcessor);
    printf("\t\tMaximum warps per CTA: %d\n",(deviceProp.maxThreadsPerBlock/deviceProp.warpSize));
    printf("\t\tMaximum warps per SM: %d\n",(deviceProp.maxThreadsPerMultiProcessor/deviceProp.warpSize));
    printf("\t\tMaximum grid size: ");
    for (int i=0; i<3; i++)
      printf("%d ",deviceProp.maxGridSize[i]);
    printf("\n");
    printf("\t\tMaximum CTA size: ");
    for (int i=0; i<3; i++)
      printf("%d ",deviceProp.maxThreadsDim[i]);
    printf("\n");

    printf("\tMemory Properties:\n");
    printf("\t\tTotal global memory: %ld bytes\n",deviceProp.totalGlobalMem);
    printf("\t\tTotal constant memory: %ld bytes\n",deviceProp.totalConstMem);
    printf("\t\tL2 cache size: %d bytes\n",deviceProp.l2CacheSize);
    printf("\t\tShared memory per block: %ld bytes\n",deviceProp.sharedMemPerBlock);
    printf("\t\tRegisters per block: %d\n",deviceProp.regsPerBlock);
    size_t stackSize,pfSize,heapSize;
    CUDA_SAFE_CALL(cudaDeviceGetLimit(&stackSize, cudaLimitStackSize));
    CUDA_SAFE_CALL(cudaDeviceGetLimit(&pfSize, cudaLimitPrintfFifoSize));
    CUDA_SAFE_CALL(cudaDeviceGetLimit(&heapSize, cudaLimitMallocHeapSize));
    printf("\t\tStack size per thread: %ld bytes\n",stackSize);
    printf("\t\tMalloc heap size: %ld bytes\n",heapSize);
    printf("\t\tPrintf buffer size: %ld bytes\n",pfSize);
    printf("\t\tMemory bus width: %d bits\n",deviceProp.memoryBusWidth); 
    printf("\t\tMemory pitch: %ld bytes\n",deviceProp.memPitch);

    printf("\tPCI-E Xfer Properties:\n");
    printf("\t\tNumber of asynchronous engines (async-copy enabled): %d\n",deviceProp.asyncEngineCount);
    printf("\t\tCan Map Host Memory: %d\n",deviceProp.canMapHostMemory);
    printf("\t\tPCI device ID: %d\n",deviceProp.pciDeviceID);
    printf("\t\tPCI bus ID: %d\n",deviceProp.pciBusID);
    
    printf("\n\n");
  }

  return 0;
}
