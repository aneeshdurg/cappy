#include <cstdint>
#include <stdio.h>

// For the CUDA runtime routines (prefixed with "cuda_")
#include <cuda_runtime.h>

#define IPV4(a, b, c, d)                                                       \
  ({                                                                           \
    uint32_t ipv4 = a;                                                         \
    ipv4 = ipv4 * 256 + b;                                                     \
    ipv4 = ipv4 * 256 + c;                                                     \
    ipv4 = ipv4 * 256 + d;                                                     \
    ipv4;                                                                      \
  })

__device__ uint32_t access_u32(char *d_pcap, uint64_t offset) {
  // only aligned accesses are allowed, so we need to align offset to a 32b
  // boundry
  auto rem = offset % 4;
  auto start = offset - rem;

  auto first = *(uint32_t *)(d_pcap + start);
  auto last = *(uint32_t *)(d_pcap + start + 4);

  // get the last `rem` bytes from `first` and the first `4 - rem` bytes from
  // last
  first <<= 8 * (4 - rem);
  last >>= 8 * rem;

  return first | last;
}

/**
 * CUDA Kernel Device code
 *
 * Computes the vector addition of A and B into C. The 3 vectors have the same
 * number of elements numElements.
 */
__global__ void filterpckts(uint64_t *d_offsets, char *d_pcap, uint32_t *output,
                            uint64_t n_pkts) {
  int i = blockDim.x * blockIdx.x + threadIdx.x;
  if (i > n_pkts) {
    return;
  }

  constexpr size_t pcap_pkt_header = 16;
  constexpr size_t ethernet_header = 14;
  constexpr size_t header_offset = pcap_pkt_header + ethernet_header;

  auto offset = d_offsets[i];
  uint32_t ip_src = access_u32(d_pcap, offset + header_offset + 12);
  // uint32_t ip_dst = *(int32_t *)(d_pcap + offset + header_offset + 16);
  output[i] = 0;
  // if (ip_src == IPV4(192, 168, 68, 110)) {
  if (ip_src == IPV4(21, 98, 0, 0)) {
    output[i] = 1;
  }
}

#define CuAlloc(sz)                                                            \
  ({                                                                           \
    void *tmp = NULL;                                                          \
    auto err = cudaMalloc(&tmp, sz);                                           \
    if (tmp == NULL) {                                                         \
      fprintf(stderr, "Failed to allocate device vector!\n");                  \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
    tmp;                                                                       \
  })

extern "C" {

// Returns res[i] = pkt i passed filter ? true : false
char *cappy_main(size_t n_pkts, uint64_t *const pkt_offsets, char *const pcap,
                 size_t pcap_size) {
  // Error code to check return values for CUDA calls
  cudaError_t err = cudaSuccess;

  auto offsets_size = n_pkts * sizeof(uint64_t);
  uint64_t *d_offsets = (uint64_t *)CuAlloc(offsets_size);
  char *d_pcap = (char *)CuAlloc(pcap_size);
  uint32_t *d_output = (uint32_t *)CuAlloc(n_pkts * sizeof(uint32_t));

  // Copy the host input vectors A and B in host memory to the device input
  // vectors in device memory
  printf("Copy input data from the host memory to the CUDA device\n");
  err =
      cudaMemcpy(d_offsets, pkt_offsets, offsets_size, cudaMemcpyHostToDevice);
  if (err != cudaSuccess) {
    fprintf(stderr,
            "Failed to copy vector A from host to device (error code %s)!\n",
            cudaGetErrorString(err));
    exit(EXIT_FAILURE);
  }

  err = cudaMemcpy(d_pcap, pcap, pcap_size, cudaMemcpyHostToDevice);
  if (err != cudaSuccess) {
    fprintf(stderr,
            "Failed to copy vector A from host to device (error code %s)!\n",
            cudaGetErrorString(err));
    exit(EXIT_FAILURE);
  }

  // Launch the Vector Add CUDA Kernel
  int threadsPerBlock = 256;
  int blocksPerGrid = (n_pkts + threadsPerBlock - 1) / threadsPerBlock;
  printf("CUDA kernel launch with %d blocks of %d threads\n", blocksPerGrid,
         threadsPerBlock);
  filterpckts<<<blocksPerGrid, threadsPerBlock>>>(d_offsets, d_pcap, d_output,
                                                  n_pkts);
  err = cudaGetLastError();

  if (err != cudaSuccess) {
    fprintf(stderr, "Failed to launch vectorAdd kernel (error code %s)!\n",
            cudaGetErrorString(err));
    exit(EXIT_FAILURE);
  }

  char *h_output = (char *)malloc(n_pkts * sizeof(uint32_t));
  if (h_output == NULL) {
    fprintf(stderr, "failed to allocate host output\n");
    exit(EXIT_FAILURE);
  }

  // Copy the device result vector in device memory to the host result vector
  // in host memory.
  printf("Copy output data from the CUDA device to the host memory\n");
  err = cudaMemcpy(h_output, d_output, n_pkts * sizeof(uint32_t),
                   cudaMemcpyDeviceToHost);
  if (err != cudaSuccess) {
    fprintf(stderr,
            "Failed to copy output from device to host (error code %s)!\n",
            cudaGetErrorString(err));
    exit(EXIT_FAILURE);
  }

  // Free device global memory
  err = cudaFree(d_offsets);
  if (err != cudaSuccess) {
    fprintf(stderr, "Failed to free device vector offsets (error code %s)!\n",
            cudaGetErrorString(err));
    exit(EXIT_FAILURE);
  }

  err = cudaFree(d_pcap);
  if (err != cudaSuccess) {
    fprintf(stderr, "Failed to free device vector pcaps (error code %s)!\n",
            cudaGetErrorString(err));
    exit(EXIT_FAILURE);
  }

  err = cudaFree(d_output);
  if (err != cudaSuccess) {
    fprintf(stderr, "Failed to free device vector output (error code %s)!\n",
            cudaGetErrorString(err));
    exit(EXIT_FAILURE);
  }

  // Reset the device and exit
  // cudaDeviceReset causes the driver to clean up all state. While
  // not mandatory in normal operation, it is good practice.  It is also
  // needed to ensure correct operation when the application is being
  // profiled. Calling cudaDeviceReset causes all profile data to be
  // flushed before the application exits
  err = cudaDeviceReset();
  if (err != cudaSuccess) {
    fprintf(stderr, "Failed to deinitialize the device! error=%s\n",
            cudaGetErrorString(err));
    exit(EXIT_FAILURE);
  }

  printf("Done retval=%p\n", h_output);
  return h_output;
}
}
