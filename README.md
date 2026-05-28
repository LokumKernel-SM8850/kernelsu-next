# LokumKernel KernelSU Next Integration

This repository is the LokumKernel-SM8850 integration mirror for KernelSU Next.
It is not the upstream KernelSU Next project and it is not something users need
to install separately on the phone.

## Purpose

LokumKernel builds KernelSU Next into the kernel tree through
`kernel_platform/common/drivers/kernelsu`, which is a symlink to this repository's
`kernel/` directory in the local build workspace.

This mirror exists so LokumKernel releases can pin and audit the exact KernelSU
Next + SUSFS integration commit used for a kernel build.

## Upstream

- KernelSU Next upstream: https://github.com/KernelSU-Next/KernelSU-Next
- SUSFS upstream/reference: https://gitlab.com/simonpunk/susfs4ksu

## Current Lokum branch

- Branch: `lokum/dev-susfs-c2013a15`
- Purpose: KernelSU Next dev integration with SUSFS v2.1.0 for LokumKernel SM8850

Runtime artifacts are produced by `LokumKernel-SM8850/lokum-release`; this
repository only carries source used during kernel compilation.
