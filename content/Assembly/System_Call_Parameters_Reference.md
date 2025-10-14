---
title: "System Call Parameters Reference"
source: "System Call Parameters Reference.html"
---

# System Call Parameters Reference

| Parameter | Typical Usage / Analysis | Code Example |
|-----------|--------------------------|--------------|
| fd        | Integer representing an open file/socket. `0=stdin`, `1=stdout`, `2=stderr`. Values ≥3 returned by `open()`, `socket()`. | `read(0, buf, 100);` |
| filename  | Path to a file (string). Absolute/relative. | `open("/etc/passwd", O_RDONLY);` |
| buf       | Pointer to memory buffer, stores data. | `read(fd, buf, 100);` |
| count / size | Bytes to read/write. | `write(fd, buf, 64);` |
| flags     | Bitwise OR constants (e.g. `O_RDONLY`, `O_CREAT`). | `open("log.txt", O_WRONLY | O_CREAT);` |
| mode      | Permission bits if `O_CREAT` used (`0644`, `0755`). | `open("file.txt", O_CREAT, 0644);` |
| offset    | File position for seeking. | `lseek(fd, 0, SEEK_SET);` |
| whence    | Reference for offset (`SEEK_SET`, `SEEK_CUR`, `SEEK_END`). | `lseek(fd, 10, SEEK_CUR);` |
| pid       | Process ID used in syscalls. | `kill(1234, SIGKILL);` |
| sig       | Signal number (`9=SIGKILL`, `15=SIGTERM`). | `kill(pid, SIGTERM);` |
| pathname  | Like filename, used in file/directory syscalls. | `stat("/tmp/log", &statbuf);` |
| statbuf   | Pointer to `struct stat` with metadata. | `stat(pathname, &statbuf);` |
| uaddr     | User-space address pointer (futex). | `futex(&lock, FUTEX_WAIT, 1, NULL);` |
| val       | Integer value (expected memory state, etc). | `futex(&lock, FUTEX_WAIT, 1, NULL);` |
| timeout   | Pointer to time struct (`timeval`/`timespec`). | `select(3, &fds, NULL, NULL, &timeout);` |

_Source: System Call Parameters Reference.html._
