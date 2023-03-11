## Developer Notes

#### Building

See [INSTALL.md](INSTALL.md) for build instructions.
[SMALL.md](SMALL.md) has hints for building smaller binaries, also see comments in [default_options.h](./src/default_options.h).

To be able to debug add `-g` compiler option to the `CFLAGS` environment variable. This will generate debug symbols.
```
export CFLAGS="$CFLAGS -g"
```

#### File dependencies
The GitHub [test build script](./.github/workflows/build.yml) requires the [default_options.h](./src/default_options.h) be at the top of the repository tree. The script uses the file to generate localoptions.h with various features enabled/disabled.

Following are generated files in the format \<target\>: \<generator\>(\<source\>)
```
- configure: autoconf(configure.ac)
- config.h.in: autoheader(configure.ac)
- config.h: configure(config.h.in)
- Makefile: configure(Makefile.in)
- default_options_guard.h: make(default_options.h)
```
Although generated, the first two files are checked in as they change very infrequently.

#### Debug printing

Set `#define DEBUG_TRACE 1` in [localoptions.h](./localoptions.h) to enable a `-v` option for dropbear and dbclient. That prints various details of the session. For development running `dropbear -F -E` is useful to run in the foreground. You can set `#define DEBUG_NOFORK 1` to make dropbear a one-shot server, easy to run under a debugger.

#### Random sources

Most cryptography requires a good random entropy source, both to generate secret keys and in the course of a session. Dropbear uses the Linux kernel's `getrandom()` syscall to ensure that the system RNG has been initialised before using it. On some systems there is insufficient entropy gathered during early boot - generating hostkeys then will block for some amount of time. Dropbear has a `-R` option to generate hostkeys upon the first connection as required - that will allow the system more time to gather entropy.

#### Algorithms

Default algorithm lists are specified in [common-algo.c](./src/common-algo.c). They are in priority order, the client's first matching choice is used (see [rfc4253](https://www.rfc-editor.org/rfc/rfc4253.html)). Dropbear client has `-c` and `-m` arguments to choose which are enabled at runtime (doesn't work for server as of June 2020).

Enabling/disabling algorithms is done in [localoptions.h](./localoptions.h), see [default_options.h](./src/default_options.h).

#### Style

Source code is indented with tabs, width set to 4 (though width shouldn't matter much). Braces are on the same line as functions/loops/if - try to keep consistency with existing code.

All `if` statements should have braces, no exceptions.

Avoid using pointer arithmetic, instead the functions in [buffer.h](./src/buffer.h) should be used.

Some Dropbear platforms have old compilers. Variable declarations must be at the top of a scope and comments must be `/* */` rather than `//`.

Pointer variables should be initialised to NULL - it can reduce the severity of bugs.

#### Third party code

Libtomcrypt and libtommath are periodically synced from upstream, so avoid making changes to that code which will need to be maintained. Improvements can be sent upstream to the libtom project.

#### Non-root user

Dropbear server will run fine as a non-root user, allowing logins only for that user. Password authentication probably won't work (can't read shadow passwords). You will need to create hostkeys that are readable.

#### Connection setup

Dropbear implements `first_kex_packet_follows` to reduce handshake latency [RFC 4253 7.1](https://www.rfc-editor.org/rfc/rfc4253.html#section-7.1). Some less common implementations don't handle that - it can be a cause of problems connecting. Note also that Dropbear may send several ssh packets within a single TCP packet - it's just a stream.
