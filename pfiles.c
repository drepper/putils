/* Copyright (C) 2012 Ulrich Drepper <drepper@gmail.com>

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.  */

#include <argp.h>
#include <assert.h>
#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libintl.h>
#include <search.h>
#include <stdbool.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/magic.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>

#define N_(msgid)      msgid


/* Name and version of program.  */
static void print_version(FILE* stream, struct argp_state* state);
void (*argp_program_version_hook)(FILE*, struct argp_state*) = print_version;

/* Bug report address.  */
const char* argp_program_bug_address = N_("https://github.com/drepper/putils/issues");


/* Definitions of arguments for argp functions.  */
static const struct argp_option options[] = {
  { NULL, 0, NULL, 0, N_("Output mode options"), 0 },
  { "non-verbose", 'n', NULL, 0, N_("Non-verbose mode"), 0 },
  /* Ignored for compatibility with Solaris.  */
  { NULL, 'F', NULL, OPTION_HIDDEN, NULL, 0 },
  { NULL, 0, NULL, 0, NULL, 0 }
};

/* Short description of program.  */
static const char doc[] = N_("Show information about all open files in each process.");


/* Prototype for option handler.  */
static error_t parse_opt(int key, char* arg, struct argp_state* state);

/* Data structure to communicate with argp functions.  */
static struct argp argp = {
  options, parse_opt, NULL, doc, NULL, NULL, NULL
};

/* Mode selection.  */
static enum { mode_verbose = 0, mode_nonverbose } mode;


/* Information from /proc/net/unix.   */
struct info_net_unix {
  unsigned long long int inode;
  unsigned long int type;
  char path[0];
};
static void* proc_net_unix;

/* Information from /proc/net/{tcp,udp,udplite}{,6}.  raw{,6}?  */
struct info_net_ip {
  unsigned long long int inode;
  unsigned int domain;
  unsigned int type;
  unsigned int proto;
  union {
    struct sockaddr_in v4[2];
    struct sockaddr_in6 v6[2];
  };
};
static void* proc_net_ip;

/* Information from /proc/net/netlink.  */

/* Information from /proc/net/packet.  */

/* Prototypes for local functions.  */
static void handle_file(pid_t pid, int proc_dfd, int fdinfo_dfd,
                        const char* fname, int fd);
static int fd_filter(const struct dirent64* d);
static void read_proc_net_unix(void);
static int net_unix_compare(const void* p1, const void* p2);
static void read_proc_net_ip(void);
static int net_ip_compare(const void* p1, const void* p2);


int main(int argc, char* argv[])
{
  /* Parse and process arguments.  */
  int remaining;
  argp_parse(&argp, argc, argv, 0, &remaining, NULL);

  if (remaining == argc) {
    error(0, 0, gettext("missing operand"));
    argp_help(&argp, stderr, ARGP_HELP_SEE, program_invocation_short_name);
    return 1;
  }

  do {
    errno = 0;
    char* endp;
    __auto_type pid = strtol(argv[remaining], &endp, 0);
    if (*endp != '\0' || pid < 0) {
      error(0, 0, gettext("invalid PID argument \"%s\"\n"), argv[remaining]);
      continue;
    }
    assert(sizeof(pid_t) == sizeof(int) || sizeof(pid_t) == sizeof(long int));
    if ((pid == LONG_MAX && errno == ERANGE) || (sizeof(pid_t) < sizeof(long int) && pid > INT_MAX)) {
      error(0, 0, gettext("PID value %s too large\n"), argv[remaining]);
      continue;
    }

    static int fd_checked;
    char buf[MAX (15 + 3 * sizeof(pid_t), PATH_MAX)];
    snprintf(buf, sizeof(buf), "/proc/%ld", pid);
    int dfd = open64(buf, O_RDONLY | O_DIRECTORY);
    if (dfd == -1) {
      if (errno == EACCES)
        error(0, 0, gettext("insufficient privileges to read information of process %ld"), pid);
      else if (errno == ENOENT) {
        if (fd_checked == 0) {
          struct statfs st;
          if (statfs("/proc/self", &st) < 0 || st.f_type != PROC_SUPER_MAGIC)
            error(EXIT_FAILURE, errno, gettext("FATAL: proc filesystem not available"));

          fd_checked = 1;
        }

        error(0, 0, gettext("no process with PID %ld"), pid);
      } else
        error(0, errno, gettext("cannot read proc entry for process %ld"), pid);

      continue;
    }

    unsigned long long int nopen = 0;
    int dfd2 = -1;
    struct dirent64** fds = NULL;
#ifdef HAVE_SCANDIRAT
    int nfds = scandirat64(dfd, "fd", &fds, fd_filter, versionsort64);
#else
    snprintf(buf, sizeof(buf), "/proc/%ld/fd", pid);
    int nfds = scandir64(buf, &fds, fd_filter, versionsort64);
#endif
    if (nfds == -1) {
      if (errno == EACCES)
        error(0, 0, gettext ("insufficient privileges to read file descriptors of process %ld"), pid);
      else
        error (0, errno, gettext ("cannot read file descriptor of process %ld"), pid);

      goto next;
    }

    if (mode == mode_verbose) {
      dfd2 = openat(dfd, "fdinfo", O_RDONLY | O_DIRECTORY);
      if (dfd2 == -1) {
        static int fdinfo_checked;
        if (fdinfo_checked == 0) {
          struct stat64 st;
          if (stat64("/proc/self/fdinfo", &st) < 0) {
            error(0, 0, gettext("proc filesystem does not provide fdinfo; falling back to non-verbose mode"));
            mode = mode_nonverbose;
          }

          fdinfo_checked = 1;
        }

        if (mode == mode_verbose) {
          error(0, errno, gettext("cannot get descriptor for %s"), buf);
          goto next2;
        }
      }
    }

    int fd;
    {
      FILE* fp;
      char* lbuf = NULL;
      size_t lbuflen = 0;
      fd = openat(dfd, "limits", O_RDONLY);
      if (fd == -1 || (fp = fdopen(fd, "r")) == NULL) {
        error(0, errno, gettext("cannot get limits of executable %ld"), pid);
        if (fd != -1)
          close(fd);
        goto next3;
      }
      __fsetlocking(fp, FSETLOCKING_BYCALLER);
      while (!feof_unlocked(fp)) {
        ssize_t n = getline(&lbuf, &lbuflen, fp);
        if (n < 0)
          break;

        assert(sizeof(rlim_t) <= sizeof(unsigned long long int));
        if (sscanf(lbuf, "Max open files %llu", &nopen) == 1)
          break;
      }
      free(lbuf);
      fclose(fp);
    }

    fd = openat(dfd, "cmdline", O_RDONLY);
    if (fd == -1) {
      error(0, errno, gettext("cannot read command line of process %ld"), pid);
      goto next3;
    }

    {
      ssize_t n = readlinkat(dfd, "exe", buf, sizeof(buf) - 1);
      bool skip = true;
      if (n > 0)
        buf[n] = '\0';
      else {
        buf[0] = '\0';
        skip = false;
      }

      printf("%ld:\t%s", pid, buf);
      while ((n = read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; ++i)
          if (buf[i] == '\0') {
            buf[i] = ' ';

            if (skip) {
              if (n > i)
                memmove(buf, &buf[i], n - i);
              n -= i;
              i = 0;

              skip = false;
            }
          }

        fwrite(buf, n, 1, stdout);
      }
      putchar_unlocked('\n');
      close(fd);
    }

    if (nopen != 0)
      printf(ngettext("  Current rlimit: %llu file descriptor\n",
                      "  Current rlimit: %llu file descriptors\n",
                      (unsigned long int) nopen), nopen);

    for (int i = 0; i < nfds; ++i)
      handle_file(pid, dfd, dfd2, fds[i]->d_name, atoi(fds[i]->d_name));

  next3:
    if (dfd2 != -1)
      close(dfd2);
  next2:
    for (int i = 0; i < nfds; ++i)
      free(fds[i]);
    free(fds);
  next:
    close(dfd);
  } while (++remaining < argc);

  /* Free process system data.  */
  tdestroy(proc_net_unix, free);
  tdestroy(proc_net_ip, free);

  return error_message_count != 0;
}


/* Handle program arguments.  */
static error_t parse_opt(int key, char* arg __attribute__((unused)), struct argp_state* state __attribute__((unused)))
{
  switch (key) {
  case 'n':
    mode = mode_nonverbose;
    break;
  case 'F':
    /* Ignored.  */
    break;
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}


/* Print the version information.  */
static void print_version(FILE* stream, struct argp_state* state __attribute__((unused)))
{
  fprintf(stream, "pfiles (%s) %s\n", "putils", VERSION);
  fprintf(stream, gettext("Copyright (C) %s Ulrich Drepper <drepper@gmail.com>.\n"), "2019");
  fprintf(stream, gettext("Written by %s.\n"), "Ulrich Drepper");
}


static const char *const sock_names[] = {
#define S(name) [name] = #name
  S (SOCK_STREAM),
  S (SOCK_DGRAM),
  S (SOCK_RAW),
  S (SOCK_RDM),
  S (SOCK_SEQPACKET),
  S (SOCK_DCCP),
  S (SOCK_PACKET)
#undef S
};
#define nsock_names (sizeof(sock_names) / sizeof(sock_names[0]))
#define get_sock_name(id) ((id) >= nsock_names || sock_names[id] == NULL \
                           ? "SOCK_???" : sock_names[id])


static void handle_file(pid_t pid, int proc_dfd, int fdinfo_dfd, const char* fname, int fd)
{
  struct stat64 st;
  char fd_fname[sizeof("fd/") + 3 * sizeof(pid_t)];
  strcpy(stpcpy(fd_fname, "fd/"), fname);
  if (fstatat64(proc_dfd, fd_fname, &st, 0) != 0) {
    error(0, errno, gettext("cannot get information about descriptor %s of process %ld"), fname, (long int) pid);
    return;
  }

#define MODE_TO_TYPE(m) (((m) & S_IFMT) >> 12)
#define TYPE_TO_MODE(t) ((t) << 12)
  assert(TYPE_TO_MODE(MODE_TO_TYPE(S_IFMT)) == S_IFMT);
  static const char *const st_types[] = {
#define S(n) [MODE_TO_TYPE (n)] = #n
    S (S_IFIFO),
    S (S_IFCHR),
    S (S_IFDIR),
    S (S_IFBLK),
    S (S_IFREG),
    S (S_IFLNK),
    S (S_IFSOCK)
#undef S
  };

  printf("%4d: %s mode:%#04o dev:%u,%u ino:%llu uid:%d gid:%d",
         fd, st_types[MODE_TO_TYPE (st.st_mode)] ?: "S_IF???",
         st.st_mode & ACCESSPERMS,
         gnu_dev_major(st.st_dev), gnu_dev_minor(st.st_dev),
         (unsigned long long int) st.st_ino,
         (int) st.st_uid, (int) st.st_gid);

  if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))
    printf(" rdev:%u,%u", gnu_dev_major(st.st_rdev), gnu_dev_minor(st.st_rdev));
  else
    printf(" size:%llu", (unsigned long long int) st.st_size);

  putchar_unlocked('\n');

  if (mode == mode_verbose) {
    int fdinfo = openat(fdinfo_dfd, fname, O_RDONLY);
    if (fdinfo == -1) {
      error(0, errno, gettext("cannot read fdinfo"));
      return;
    }

    FILE* fp = fdopen(fdinfo, "r");
    if (fp == NULL)
      error(EXIT_FAILURE, errno, gettext("fdopen failed"));

    int flags = -1;
    char* lbuf = NULL;
    size_t lbuflen = 0;
    while (!feof_unlocked(fp)) {
      __auto_type n = getline(&lbuf, &lbuflen, fp);
      if (n < 0)
        break;

      if (sscanf(lbuf, "flags: %o", &flags) == 1)
        break;
    }

    free(lbuf);
    fclose(fp);

    if (flags != -1) {
      const char* accstr;
      switch (flags & O_ACCMODE) {
      case O_RDONLY:
        accstr = "O_RDONLY";
        break;
      case O_WRONLY:
        accstr = "O_WRONLY";
        break;
      case O_RDWR:
        accstr = "O_RDWR";
        break;
      default:
        accstr = "O_???";
        break;
      }
      printf("      %s", accstr);

      int cloexec = flags & O_CLOEXEC;
      flags &= ~(O_ACCMODE | O_CLOEXEC);
      static const struct {
        int mask;
        const char* str;
      } fflags[] = {
#define S(v) { v, #v }
        S (O_CREAT),
        S (O_EXCL),
        S (O_NOCTTY),
        S (O_TRUNC),
        S (O_APPEND),
        S (O_NONBLOCK),
        S (O_SYNC),
        S (O_ASYNC),
        S (O_DIRECTORY),
        S (O_NOFOLLOW),
        S (O_DIRECT),
        S (O_NOATIME),
        S (O_PATH),
        S (O_DSYNC),
        // On 64-bit machines O_LARGEFILE is zero
        { 0100000, "O_LARGEFILE" }
#undef S
      };
#define nfflags (sizeof(fflags) / sizeof(fflags[0]))

      for (size_t i = 0; i < nfflags && flags != 0; ++i)
        if ((flags & fflags[i].mask) == fflags[i].mask) {
          printf("|%s", fflags[i].str);
          flags ^= fflags[i].mask;
        }

      if (flags != 0)
        printf("|%0o", flags);

      if (cloexec)
        fputs_unlocked(" FD_CLOEXEC", stdout);

      putchar_unlocked('\n');

      switch (st.st_mode & S_IFMT) {
        char path[PATH_MAX + 1];
        ssize_t n;

      case S_IFSOCK:
        if (proc_net_unix == NULL)
          read_proc_net_unix();
        if (proc_net_unix != (void*) -1) {
          struct info_net_unix search = { .inode = st.st_ino };
          struct info_net_unix** u = tfind(&search, &proc_net_unix, net_unix_compare);
          if (u != NULL) {
            const char* space_sock = "";
            const char* name_sock = "";
            const char* space_peer = "";
            const char* name_peer = "";
            if ((*u)->path[0] == '@') {
              space_peer = " ";
              name_peer = (*u)->path + 1;
            } else if ((*u)->path[0] != '\0') {
              space_sock = " ";
              name_sock = (*u)->path;
            }

            printf("\t%s\n"
                   "\tsockname: AF_UNIX%s%s\n"
                   "\tpeername: AF_UNIX%s%s\n",
                   get_sock_name ((*u)->type),
                   space_sock, name_sock,
                   space_peer, name_peer);
            break;
          }
        }

        if (proc_net_ip == NULL)
          read_proc_net_ip();
        if (proc_net_ip != (void*) -1l) {
          struct info_net_ip search = { .inode = st.st_ino };
          struct info_net_ip** u = tfind(&search, &proc_net_ip, net_ip_compare);
          if (u != NULL) {
            const char* domain;
            const void* localaddr;
            uint16_t localport;
            const void* remoteaddr;
            uint16_t remoteport;
            if ((*u)->domain == AF_INET) {
              domain = "AF_INET";
              localaddr = &(*u)->v4[0].sin_addr;
              localport = (*u)->v4[0].sin_port;
              remoteaddr = &(*u)->v4[1].sin_addr;
              remoteport = (*u)->v4[1].sin_port;
            } else {
              domain = "AF_INET6";
              localaddr = &(*u)->v6[0].sin6_addr;
              localport = (*u)->v6[0].sin6_port;
              remoteaddr = &(*u)->v6[1].sin6_addr;
              remoteport = (*u)->v6[1].sin6_port;
            }

            const char* protostr = ((*u)->proto == IPPROTO_UDPLITE ? " IPPROTO_UDPLITE" : "");

            char localstr[INET6_ADDRSTRLEN];
            char remotestr[INET6_ADDRSTRLEN];
            printf("\t%s%s\n"
                   "\tsockname: %s %s  port: %" PRIu16 "\n"
                   "\tpeername: %s %s  port: %" PRIu16 "\n",
                   get_sock_name((*u)->type),
                   domain, protostr,
                   inet_ntop((*u)->domain, localaddr, localstr, sizeof(localstr)),
                   localport,
                   domain,
                   inet_ntop((*u)->domain, remoteaddr, remotestr, sizeof(remotestr)),
                   remoteport);
            break;
          }
        }
        break;

      case S_IFREG:
      case S_IFDIR:
      case S_IFCHR:
      case S_IFBLK:
        n = readlinkat(proc_dfd, fd_fname, path, sizeof(path));
        if (n > 0) {
          path[n] = '\0';
          printf("      %s\n", path);
        }
        break;

      default:
        /* Nothing.  */
        break;
      }
    }
  }
}


static int fd_filter(const struct dirent64 *d)
{
  if (d->d_type != DT_LNK && d->d_type != DT_UNKNOWN)
    return 0;

  char* endp;
  errno = 0;
  __auto_type n = strtol(d->d_name, &endp, 10);
  if (*endp != '\0' || (n == LONG_MAX && errno == ERANGE) || n < 0 || (INT_MAX < LONG_MAX && n > INT_MAX))
    return 0;

  return 1;
}


static int net_unix_compare(const void* p1, const void* p2)
{
  __auto_type i1 = (const struct info_net_unix*) p1;
  __auto_type i2 = (const struct info_net_unix*) p2;

  if (i1->inode == i2->inode)
    return 0;

  return i1->inode < i2->inode ? -1 : 1;
}


static void read_proc_net_unix(void)
{
  FILE *fp = fopen("/proc/net/unix", "r");
  if (fp == NULL) {
    proc_net_unix = (void*) -1l;
    error(0, errno, gettext("cannot read /proc/net/unix"));
    return;
  }

  char buf[getpagesize()];
  setvbuf(fp, buf, _IOFBF, sizeof(buf));
  __fsetlocking(fp, FSETLOCKING_BYCALLER);

  char* line = NULL;
  size_t linelen = 0;
  while (! feof_unlocked(fp)) {
    __auto_type n = getline(&line, &linelen, fp);
    if (n < 0)
      break;

    /* Remove the newline.  */
    assert(line[n - 1] == '\n');
    line[n - 1] = '\0';

    unsigned long long int inode;
    unsigned long int type;
    int off;
    int cnt = sscanf(line, "%*x: %*x %*x %*x %lx %*x %llu %n", &type, &inode, &off);
    if (cnt == 2) {
      const char* path = line + off;
      size_t pathlen = strlen(path) + 1;
      struct info_net_unix *newp = malloc(sizeof(*newp) + pathlen);
      if (newp == NULL)
        error(EXIT_FAILURE, errno, gettext("cannot allocate memory"));

      newp->inode = inode;
      newp->type = type;
      memcpy(newp->path, path, pathlen);

      void* p = tsearch(newp, &proc_net_unix, &net_unix_compare);
      assert(*((struct info_net_unix **) p) == newp);
    }
  }

  free(line);
  fclose(fp);
}


static int net_ip_compare (const void* p1, const void* p2)
{
  __auto_type i1 = (const struct info_net_ip*) p1;
  __auto_type i2 = (const struct info_net_ip*) p2;

  if (i1->inode == i2->inode)
    return 0;

  return i1->inode < i2->inode ? -1 : 1;
}


static void read_proc_X(const char* fname, int domain, int type, int proto)
{
  FILE* fp = fopen(fname, "r");
  if (fp == NULL)
    return;

  char buf[getpagesize()];
  setvbuf(fp, buf, _IOFBF, sizeof(buf));
  __fsetlocking(fp, FSETLOCKING_BYCALLER);

  char* line = NULL;
  size_t linelen = 0;
  while (! feof_unlocked(fp)) {
    __auto_type n = getline(&line, &linelen, fp);
    if (n < 0)
      break;

    char localaddr[33];
    char localport[5];
    char remoteaddr[33];
    char remoteport[5];
    unsigned long long int inode;
    int cnt = sscanf(line,
                     "%*d: %[0123456789ABCDEF]:%[0123456789ABCDEF] %[0123456789ABCDEF]:%[0123456789ABCDEF] %*x %*x:%*x %*x:%*x %*x %*d %*d %llu",
                     localaddr, localport, remoteaddr, remoteport, &inode);
    if (cnt == 5) {
      struct info_net_ip *newp = malloc(sizeof(*newp));
      if (newp == NULL)
        error(EXIT_FAILURE, errno, gettext("cannot allocate memory"));

      newp->inode = inode;
      newp->domain = domain;
      newp->type = type;
      newp->proto = proto;

      if (domain == AF_INET) {
        newp->v4[0].sin_addr.s_addr = strtoul (localaddr, NULL, 16);
        newp->v4[0].sin_port = strtoul (localport, NULL, 16);
        newp->v4[1].sin_addr.s_addr = strtoul (remoteaddr, NULL, 16);
        newp->v4[1].sin_port = strtoul (remoteport, NULL, 16);
      } else {
        uint8_t* wp;
        char* cp;
#if BYTE_ORDER == LITTLE_ENDIAN
        wp = &newp->v6[0].sin6_addr.s6_addr[0];
        cp = localaddr;
        for (int i = 0; i < 16; cp += 2, ++i)
          *wp++ = cp[0] - (isdigit(cp[0]) ? '0' : ('A' + 10));
        wp = &newp->v6[1].sin6_addr.s6_addr[0];
        cp = remoteaddr;
        for (int i = 0; i < 16; cp += 2, ++i)
          *wp++ = cp[0] - (isdigit(cp[0]) ? '0' : ('A' + 10));
#else
        wp = &newp->v6[0].sin6_addr.s6_addr[16];
        cp = localaddr;
        for (int i = 0; i < 16; cp += 2, ++i)
          *--wp = cp[0] - (isdigit(cp[0]) ? '0' : ('A' + 10));
        wp = &newp->v6[1].sin6_addr.s6_addr[16];
        cp = remoteaddr;
        for (int i = 0; i < 16; cp += 2, ++i)
          *--wp = cp[0] - (isdigit(cp[0]) ? '0' : ('A' + 10));
#endif

        newp->v6[0].sin6_port = ntohs(strtoul(localport, NULL, 16));
        newp->v6[1].sin6_port = ntohs(strtoul(remoteport, NULL, 16));
      }

      void* p = tsearch(newp, &proc_net_ip, &net_ip_compare);
      assert(*((struct info_net_ip**) p) == newp);
    }
  }

  free(line);
  fclose(fp);
}


static void read_proc_net_ip(void)
{
  read_proc_X("/proc/net/tcp", AF_INET, SOCK_STREAM, IPPROTO_IP);
  read_proc_X("/proc/net/udp", AF_INET, SOCK_DGRAM, IPPROTO_IP);
  read_proc_X("/proc/net/udplite", AF_INET, SOCK_DGRAM, IPPROTO_UDPLITE);
  read_proc_X("/proc/net/tcp6", AF_INET6, SOCK_STREAM, IPPROTO_IP);
  read_proc_X("/proc/net/udp6", AF_INET6, SOCK_DGRAM, IPPROTO_IP);
  read_proc_X("/proc/net/udplite6", AF_INET6, SOCK_DGRAM, IPPROTO_UDPLITE);

  if (proc_net_ip == NULL)
    proc_net_ip = (void*) -1l;
}
