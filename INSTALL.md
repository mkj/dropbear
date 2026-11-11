## Basic Dropbear Build Instructions

### Build Options

Custom build options can be configured in `localoptions.h` in the build directory. This is a local file, not checked in to git.

Available options are described in [`src/default_options.h`](src/default_options.h)
Options include available cryptographic algorithms, SSH features, and file paths.

In addition, a `src/distrooptions.h` file will be used if it exists, for distributions to set configuration options.

### Configure for your system
```
./configure
```
Optionally with `--disable-zlib` or `--disable-syslog`.
Or `--help` for other options.

You'll need to first run `autoconf; autoheader` if you edit `configure.ac`.

### Compile:

```
make PROGRAMS="dropbear dbclient dropbearkey dropbearconvert scp"
```

Optionally install, or copy the binaries another way:

```
make install
```
`/usr/local/bin` is usual default.

or

```
make PROGRAMS="dropbear dbclient dropbearkey dropbearconvert scp" install
```

To test the installation targeting a temporary forder set `DESTDIR`:
```
make install DESTDIR=/same/temp/location
```

You can leave items out of the `PROGRAMS` list to avoid compiling them.
If you recompile after changing the `PROGRAMS` list, you **MUST** `make clean` before recompiling - bad things will happen otherwise.

[DEVELOPING.md](DEVELOPING.md) has some notes on other developer topics, including debugging.

See [MULTI.md](MULTI.md) for instructions on making all-in-one binaries.

If you want to compile statically use
```
./configure --enable-static
```

By default Dropbear adds various build flags that improve robustness against programming bugs (good for security).
If these cause problems they can be disabled with `./configure --disable-harden`.

Binaries can be stripped with `make strip`.
