# 306kernels-redbull

Kernel for the Pixel 4a 5G (bramble), Pixel 5 (redfin) and Pixel 5a (barbet)
with KernelSU-Next, susfs and Droidspaces support, built by GitHub Actions
into an AnyKernel3 zip.

Branch `17.0` is crDroid's `android_kernel_google_redbull` 17.0 (itself
LineageOS lineage-24.0 plus the KernelSU-Next/susfs/Droidspaces commits).
It is meant for crDroid 17 and LineageOS 24.0 builds of these devices, as well as derivatives .

## What the zip does

| part | from the zip | why |
| --- | --- | --- |
| `boot` | `Image.lz4` | the kernel |
| `vendor_boot` ramdisk `lib/modules/*.ko` | first-stage modules | built with this kernel |
| `/vendor/lib/modules/*.ko` | all other modules | built with this kernel |

The zip ships one copy of every module the build produces. This ensures no kernel vermagic issues or ABI instability with modules built in the vanilla ROM


## Flashing

Recovery: `adb sideload 306kernels-redbull-*.zip` (accept the unsigned-zip
prompt in Lineage recovery) or flash from the recovery's file picker.
KernelFlasher also works from a booted system.

Install the KernelSU-Next manager afterwards:
- On branch `17.0`: sidex15's `legacy-susfs-v2` tree (`v3.4.0-legacy`, UAPI 4) — use the **v3.4.0** manager release.
- On branch `3.4.2-dev`: `v3.4.2-legacy-susfs` (UAPI 5) with **SUSFS v2.4.0** — use the **v3.4.2** manager release.
For root hiding use a SUSFS v2.x module (e.g. `BRENE` or `sidex15/susfs4ksu-module`).

## Cloning

Linux kernel sources contain case-sensitive filenames that differ only by case
(for example `include/uapi/linux/netfilter/xt_CONNMARK.h` vs `xt_connmark.h`).
Use a case-sensitive filesystem when cloning:

### Linux
```sh
git clone -b 3.4.2-dev https://github.com/longnguyen5512/306kernels-redbull.git
```

### macOS (Case-sensitive APFS disk image)
macOS defaults to case-insensitive APFS. Create and mount a Case-sensitive APFS
sparse image first:

```sh
hdiutil create -size 20g -type SPARSE -fs "Case-sensitive APFS" -volname "306kernels-redbull" 306kernels-redbull.sparseimage
mkdir -p 306kernels-redbull
hdiutil attach 306kernels-redbull.sparseimage -mountpoint "$PWD/306kernels-redbull" -nobrowse
cd 306kernels-redbull
git init -b 3.4.2-dev
git remote add origin https://github.com/longnguyen5512/306kernels-redbull.git
git fetch origin
git checkout -b 3.4.2-dev origin/3.4.2-dev
```

*(After rebooting macOS, re-mount with `hdiutil attach 306kernels-redbull.sparseimage -mountpoint "$PWD/306kernels-redbull" -nobrowse`.)*

### Windows (WSL2 recommended)
Clone inside **WSL2 (Ubuntu)** where `ext4` is natively case-sensitive:

```sh
wsl
cd ~
git clone -b 3.4.2-dev https://github.com/longnguyen5512/306kernels-redbull.git
```

*(If cloning onto NTFS instead, enable per-directory case sensitivity as Administrator first: `fsutil file setCaseSensitiveInfo C:\path\to\306kernels-redbull enable`.)*

## Building

### GitHub Actions
`.github/workflows/build.yml` runs on every push to `17.0` and on manual
dispatch (which also publishes a release). It uses AOSP `clang-r596125`,
`LLVM=1 LLVM_IAS=1`, `redbull_defconfig`, and `LOCALVERSION=-306kernels`.

### Linux (x86_64)
1. Install dependencies:
   ```sh
   sudo apt-get update && sudo apt-get install -y bc bison flex libssl-dev libelf-dev lz4 cpio zip curl
   ```
2. Download AOSP `clang-r596125`:
   ```sh
   mkdir -p toolchain/clang-r596125
   curl -sSL "https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+archive/refs/tags/android-17.0.0_r1/clang-r596125.tar.gz" \
     | tar -xz -C toolchain/clang-r596125
   ```
3. Build & package:
   ```sh
   CLANG_BIN="$PWD/toolchain/clang-r596125/bin" .github/ci/build.sh . out stage
   .github/ci/package.sh stage 306kernels-redbull.zip
   ```
   *(Pass `KERNEL_LTO=thin` if your machine has less than 12 GB RAM.)*

### macOS (Apple Silicon / ARM64 via Docker)
Uses native `linux/arm64` Ubuntu 24.04 + `clang`/`lld` inside Docker (no Rosetta required), syncing the source into a native `ext4` Docker volume:

1. Start **Docker Desktop** (allocate at least 8 GB RAM; 12 GB+ for `KERNEL_LTO=full`).
2. Run:
   ```sh
   cd docker
   ./build.sh
   ```
   *(Default is `KERNEL_LTO=thin` and clean `LOCALVERSION=""`. Override with `KERNEL_LTO=full ./build.sh`.)*
3. Output zip will be in `docker/out/`.

### Windows (WSL2)
Inside **WSL2 (Ubuntu)**, follow the exact **Linux (x86_64)** steps above (ensure WSL2 has >= 8 GB RAM in `%UserProfile%\.wslconfig`, or use `KERNEL_LTO=thin`).
