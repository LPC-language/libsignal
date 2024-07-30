The `libsignal` extension module provides cryptographic functions for
Hydra/DGD, required for
[signal-server](https://github.com/LPC-language/signal-server).

Building requires OpenSSL 1.1.1 or later and a git checkout of the standard DGD
[extension modules](https://github.com/dworkin/lpc-ext).  Build those first,
and then build the libsignal module with `make EXTDIR=/path/to/lpc-ext`.  The
libsignal module will be placed in the `lpc-ext` root directory.
