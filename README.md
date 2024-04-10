# This project has moved: https://github.com/ps5-payload-dev/shsrv

***

# PS5 Shell Payload
ps5-payload-shsrv is a simple Telnet server that can be executed on a Playstation 5
that has been jailbroken via the [BD-J][bdj] or the [webkit][webkit] entry points.
The server provides connected clients with a couple of basic UNIX-like commands,
e.g., cd, mkdir, stat, etc.

## Quick-start
To deploy the shell server, first launch the [ps5-payload-elfldr][elfldr], then
load the payload and connect using a telnet client by issuing the following commands:

```console
john@localhost:~$ export PS5_HOST=ps5
john@localhost:~$ wget -q -O - https://github.com/john-tornblom/ps5-payload-shsrv/releases/download/release%2Fv0.4/Payload.zip  | gunzip -c -d | nc -q0 $PS5_HOST 9021
john@localhost:~$ telnet $PS5_HOST 2323
```

## Usage
There are a handful of rudimentary commands available, e.g., cd, ls, and mkdir.
Type `help` in a connected telnet shell for more information. For example, to
get a list of running processes:
```console
/$ ps
     PID      PPID     PGID      SID      UID           AuthId          Emul  State  AppId  TitleId  Command
...
      61        50       50       50        1 480000001000000e   Native SELF   SLEEP  000e    40112  SceSpZeroConf
      60        50       50       50        0 4800000000000028   Native SELF   SLEEP  000d    40153  ScePsNowClientDaemo
      59        50       50       50        0 4800000000000019   Native SELF   SLEEP  000c    40102  SceRemotePlay
      58        50       50       50        0 4800000000001004   Native SELF   SLEEP  000b    40039  SceMediaCoreServer
      57        50       50       50        0 4800000000000014   Native SELF   SLEEP  000a    40109  ScePartyDaemon
...
```

You can also run your own paylaods by placing them in a folder included in the
PATH enviroment variable, which is initialized to /data/hbroot/bin and
/mnt/usb0/hbroot/bin

```console
john@localhost:tmp$ wget https://github.com/john-tornblom/ps5-payload-sdk/releases/download/releases%2Fv0.8/Payload.binaries.zip
john@localhost:tmp$ unzip Payload.binaries.zip samples/hello_sprx/hello_sprx.elf
john@localhost:tmp$ curl -T samples/hello_sprx/hello_sprx.elf ftp://ps5:2121/data/hbroot/bin/
john@localhost:tmp$ echo "hello_sprx.elf" | nc -q0 $PS5_HOST 2323
```

## Building
Assuming you have the [ps5-payload-sdk][sdk] installed on a Debian-flavored
operating system, the payload can be compiled using the following commands:
```console
john@localhost:ps5-payload-shsrv$ sudo apt-get install xxd
john@localhost:ps5-payload-shsrv$ export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
john@localhost:ps5-payload-shsrv$ make
```

## Limitations
The login session is not attached to a TTY, so you cannot signal for, e.g., SIGINT
with Ctrl+C. Furthermore, most of the commands are only partially implemneted.
If you find some limitation extra anoying, file a github issue and perhaps it will
be addressed.

## Reporting Bugs
If you encounter problems with ps5-payload-shsrv, please [file a github issue][issues].
If you plan on sending pull requests which affect more than a few lines of code,
please file an issue before you start to work on you changes. This will allow us
to discuss the solution properly before you commit time and effort.

## License
ps5-payload-shsrv is licensed under the GPLv3+.

[bdj]: https://github.com/john-tornblom/bdj-sdk
[sdk]: https://github.com/john-tornblom/ps5-payload-sdk
[webkit]: https://github.com/Cryptogenic/PS5-IPV6-Kernel-Exploit
[elfldr]: https://github.com/john-tornblom/ps5-payload-elfldr
[issues]: https://github.com/john-tornblom/ps5-payload-shsrv/issues/new

