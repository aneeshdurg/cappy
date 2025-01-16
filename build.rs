extern crate cc;

fn main() {
    println!("cargo::rerun-if-changed=src/kernel.cu");
    cc::Build::new()
        .cuda(true)
        .ccbin(false)
        .flag("-cudart=shared")
        .file("src/kernel.cu")
        .opt_level(3)
        .compile("libcappy_kernel.a");

    /* Link CUDA Runtime (libcudart.so) */

    // Add link directory
    // - This path depends on where you install CUDA (i.e. depends on your Linux distribution)
    // - This should be set by `$LIBRARY_PATH`
    println!("cargo:rustc-link-search=native=/usr/local/cuda/lib64");
    println!("cargo:rustc-link-lib=cudart");

    /* Optional: Link CUDA Driver API (libcuda.so) */

    // println!("cargo:rustc-link-search=native=/usr/local/cuda/lib64/stub");
    // println!("cargo:rustc-link-lib=cuda");
}
