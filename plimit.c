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
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <libintl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>

#define N_(msgid)      msgid

/* Name and version of program.  */
static void print_version(FILE* stream, struct argp_state* state);
void (*argp_program_version_hook)(FILE*, struct argp_state*) = print_version;

/* Comparison for strings.  */
static int charcmp(const void* p1, const void* p2);


/* The known limits.  */
static const struct limits {
  int limit;
  char idchar;
  enum unit {
    unit_descriptors,
    unit_seconds,
    unit_useconds,
    unit_blocks,
    unit_bytes,
    unit_kbytes,
    unit_mbytes,
    unit_processes,
    unit_none
  } unit:8;
  const char name[14];
  const char* descr;
  uint16_t kernel_name_len;
  const char kernel_name[22];
} limits[] = {
#define SNLEN(s) sizeof (s) - 1, s
  { RLIMIT_CPU, 't', unit_seconds, N_("time"),
    N_("Set CPU time limits."), SNLEN("Max cpu time") },
  { RLIMIT_FSIZE, 'f', unit_blocks, N_("file"),
    N_("set file size limits."), SNLEN("Max file size") },
  { RLIMIT_DATA, 'd', unit_bytes, N_("data"),
    N_("Set data segment limits."), SNLEN("Max data size") },
  { RLIMIT_STACK, 's', unit_bytes, N_("stack"),
    N_("Set stack size."), SNLEN("Max stack size") },
  { RLIMIT_CORE, 'c', unit_blocks, N_("coredump"),
    N_("Set core file size."), SNLEN("Max core file size") },
  { RLIMIT_RSS, 'm', unit_kbytes, N_("rss"),
    N_("Set maximum memory size."), SNLEN("Max resident set") },
  { RLIMIT_NOFILE, 'n', unit_descriptors, N_("nofile"),
    N_("Set open files limits."), SNLEN("Max open files") },
  { RLIMIT_AS, 'v', unit_bytes, N_("vmemory"),
    N_("Set virtual memory size limits."), SNLEN("Max address space") },
  { RLIMIT_NPROC, 'u', unit_processes, N_("user"),
    N_("Set maximum user process limits."), SNLEN("Max processes") },
  { RLIMIT_MEMLOCK, 'l', unit_bytes, N_("memlocks"),
    N_("Set maximum locked memory limits."), SNLEN("Max locked memory") },
  { RLIMIT_LOCKS, 'x', unit_none, N_("filelocks"),
    N_("Set file locks limits."), SNLEN("Max file locks") },
  { RLIMIT_SIGPENDING, 'i', unit_none, N_("sigpending"),
    N_("Set pending signal limits."), SNLEN("Max pending signals") },
  { RLIMIT_MSGQUEUE, 'q', unit_bytes, N_("queuesize"),
    N_("Set POSIX message queues limits."), SNLEN("Max msgqueue size") },
  { RLIMIT_NICE, 'e', unit_none, N_("schedpriority"),
    N_("Set scheduling priority limits."), SNLEN("Max nice priority") },
  { RLIMIT_RTPRIO, 'r', unit_none, N_("rtpriority"),
    N_("Set read-time priority limits."), SNLEN("Max realtime priority") },
#ifdef RLIMIT_RTTIME
    // Not yet in bash, limit selector might change.
  { RLIMIT_RTTIME, 'b', unit_useconds, N_("realtime"),
    N_("Set uninterrupted real-time scheduling limits."), SNLEN("Max realtime timeout") }
#endif
};

#define nlimits (sizeof(limits) / sizeof(limits[0]))

static const char unit_strings[][12] = {
  [unit_descriptors] = "descriptors",
  [unit_seconds] = "seconds",
  [unit_useconds] = "useconds",
  [unit_blocks] = "blocks",
  [unit_bytes] = "bytes",
  [unit_kbytes] = "kbytes",
  [unit_mbytes] = "mbytes",
  [unit_processes] = "procecesses"
};


/* Limits to set.  */
static struct opt_limit {
  rlim64_t soft;
  rlim64_t hard;
  struct opt_limit *next;
  int limit;
  bool set_hard;
} *opt_limits;


/* Bug report address.  */
const char* argp_program_bug_address = N_("https://github.com/drepper/putils/issues");

/* Option values.  */
#define OPT_KILO 256
#define OPT_MEGA 257

/* Definitions of arguments for argp functions.  */
static struct argp_option options[4 + nlimits + 1] = {
  {NULL, 0, NULL, 0, N_("Output mode options"), 2},
  {"kilo", OPT_KILO, NULL, 0, N_("Print values in kilo units."), 2},
  {"mega", OPT_MEGA, NULL, 0, N_("Print values in mega units."), 2},
  {NULL, 0, NULL, 0, N_("Limit setting operations"), 1},
  {NULL, 0, NULL, 0, NULL, 0}
};

/* Short description of program.  */
static const char doc[] = N_("Show current process limits or set process limits.");

/* Strings for arguments in help texts.  */
static char args_doc[28 + nlimits];

__attribute__ ((constructor))
static void args_doc_constr(void)
{
  for (__typeof__(nlimits) i = 0; i < nlimits; ++i) {
    // options[4 + i].name = NULL;
    options[4 + i].key = limits[i].idchar;
    options[4 + i].arg = N_("SORT,HARD");
    // options[4 + i].flags = 0;
    options[4 + i].doc = limits[i].descr;
    options[4 + i].group = 1;
  }

  int n;
  snprintf(args_doc, sizeof(args_doc), "PID...\n-[%n%*s] SOFT,HARD PID...",
           &n, (int) nlimits, "");
  for (__typeof__(nlimits) i = 0; i < nlimits; ++i)
    args_doc[n + i] = limits[i].idchar;

  qsort(&args_doc[n], nlimits, 1, charcmp);
}

/* Prototype for option handler.  */
static error_t parse_opt(int key, char* arg, struct argp_state* state);

/* Data structure to communicate with argp functions.  */
static struct argp argp = {
  options, parse_opt, args_doc, doc, NULL, NULL, NULL
};


/* Prototypes of local functions.  */
static int print_file_limits(const char *arg);


/* Output mode.  */
static enum unit output_mode = unit_none;


int main(int argc, char *argv[])
{
  /* Parse and process arguments.  */
  int remaining;
  argp_parse(&argp, argc, argv, 0, &remaining, NULL);

  if (remaining == argc) {
    error(0, 0, gettext("missing operand"));
    argp_help(&argp, stderr, ARGP_HELP_SEE, program_invocation_short_name);
    return 1;
  }

  int status = 0;
  if (opt_limits == NULL) {
    /* Iterative over the process IDs.  */
    while (remaining < argc)
      status |= print_file_limits(argv[remaining++]);

    return status;
  }

  /* Some kernels have a writable limits file per process but no
     prlimit system call.  */
  bool have_prlimit = true;

  /* Set limits to all the processes.  */
  struct opt_limit* l = opt_limits->next;
  opt_limits->next = NULL;
  opt_limits = l;

  while (remaining < argc) {
    assert(sizeof(pid_t) == sizeof(int) || sizeof(pid_t) == sizeof(long int));
    char* endp;
    errno = 0;
    __auto_type pid = strtoul(argv[remaining++], &endp, 10);
    if (*endp != '\0' || (pid == ULONG_MAX && errno == ERANGE) || (sizeof(pid_t) < sizeof(long int) && pid > INT_MAX)) {
      fprintf(stderr, gettext("invalid PID %s; ignored\n"), argv[remaining - 1]);
      continue;
    }

    l = opt_limits;
    do {
      struct rlimit64 newlimit;
      if (have_prlimit) {
        if (!l->set_hard) {
          if (prlimit64(pid, l->limit, NULL, &newlimit) != 0) {
            if (errno == ENOSYS)
              goto try_proc;

          no_read_limit:
            error(0, errno, gettext("\
cannot retrieve %s limits of process %ld"), gettext(limits[l->limit].name), pid);
            status = 1;
            continue;
          }
        } else
          newlimit.rlim_max = l->hard;
        newlimit.rlim_cur = l->soft;

        if (prlimit64(pid, l->limit, &newlimit, NULL) != 0) {
          if (errno == ENOSYS)
            goto try_proc;

          error(0, errno, ngettext("cannot set %s limit of process %ld",
                                   "cannot set %s limits of process %ld",
                                   l->set_hard ? 2 : 1),
                gettext(limits[l->limit].name), pid);
          status = 1;
        }
      } else {
        char fname[PATH_MAX];
      try_proc:
        snprintf(fname, sizeof(fname), "/proc/%ld", pid);
        int dfd = open(fname, O_RDONLY | O_DIRECTORY);
        if (dfd == -1)
          goto no_read_limit;

        int limitsfd = openat(dfd, "limits", l->set_hard ? O_RDWR : O_WRONLY);
        if (limitsfd == -1)
          goto no_read_limit;

        if (!l->set_hard) {
          char buf[4096];
          size_t next = 0;
          while (1) {
            ssize_t nr = read(limitsfd, &buf[next], sizeof (buf) - next);
            if (nr <= 0)
              break;
            next += nr;
          }
        }
      }
    }
    while ((l = l->next) != NULL);
  }

  return status;
}


static rlim64_t parse_limit(const char* arg, int limidx)
{
  if (strcasecmp(arg, "unlimited") == 0)
    return RLIM64_INFINITY;

  char* endp;
  errno = 0;
  __auto_type val = strtoull(arg, &endp, 0);
  if (val == ULLONG_MAX && errno == ERANGE)
  too_large:
    error(EXIT_FAILURE, 0, gettext("limit value %s too big"), arg);

  if (*endp != '\0') {
    unsigned int factor = 1;
    switch (limits[limidx].unit) {
    case unit_seconds:
      if (endp[0] == 'm' && endp[1] == '\0') {
        if (val > ~0ull / 60)
          goto too_large;
        val *= 60;
      } else if (endp[0] == 'h' && endp[1] == '\0') {
        if (val > ~0ull / (60 * 60))
          goto too_large;
        val *= 60 * 60;
      } else if (endp[0] == ':') {
        __auto_type val2 = strtoull(endp + 1, &endp, 0);
        if (*endp != '\0' || val2 >= 60)
          goto invalid;
        if (val > ~0ull / 60)
          goto too_large;
        val = val * 60 + val2;
      } else
      invalid:
        error(EXIT_FAILURE, 0, gettext("invalid limit %s"), arg);
      break;

    case unit_bytes:
      factor = 500;
      /* FALLTHROUGH */
    case unit_blocks:
      factor *= 2;
      /* FALLTHROUGH */
    case unit_kbytes:
      if (endp[0] == 'k' && endp[1] == '\0') {
        if (val > ~0ull / factor)
          goto too_large;
        val *= factor;
      } else if (endp[0] == 'm' && endp[1] == '\0') {
        if (val > ~0ull / (1024 * factor))
          goto too_large;
        val *= 1024 * factor;
      } else
        goto invalid;
      break;

    default:
      if (*endp != '\0')
        goto invalid;
      break;
    }
  }

  return val;
}


/* Handle program arguments.  */
static error_t parse_opt(int key, char* arg, struct argp_state* state __attribute__((unused)))
{
  switch (key) {
  case OPT_KILO:
    output_mode = unit_kbytes;
    break;
  case OPT_MEGA:
    output_mode = unit_mbytes;
    break;
  default:
    for (size_t cnt = 0; cnt < nlimits; ++cnt)
      if (key == limits[cnt].idchar) {
        char *hardp = strchr(arg, ',');
        if (hardp != NULL)
          *hardp++ = '\0';

        rlim64_t soft = parse_limit(arg, cnt);
        rlim64_t hard = hardp != NULL ? parse_limit(hardp, cnt) : 0;

        struct opt_limit *newp = malloc(sizeof(*newp));
        if (newp == NULL)
          error(EXIT_FAILURE, errno, gettext("cannot allocate memory"));

        newp->soft = soft;
        newp->hard = hard;
        newp->limit = limits[cnt].limit;
        newp->set_hard = hardp != NULL;

        if (opt_limits == NULL)
          opt_limits = newp->next = newp;
        else {
          newp->next = opt_limits->next;
          opt_limits = opt_limits->next = newp;
        }

        return 0;
      }

    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}


/* Print the version information.  */
static void print_version(FILE* stream, struct argp_state* state __attribute__((unused)))
{
  fprintf(stream, "plimit (%s) %s\n", "putils", VERSION);
  fprintf(stream, gettext("Copyright (C) %s Ulrich Drepper <drepper@gmail.com>.\n"), "2019");
  fprintf(stream, gettext("Written by %s.\n"), "Ulrich Drepper");
}


static int charcmp(const void* p1, const void* p2)
{
  __auto_type s1 = (const char*) p1;
  __auto_type s2 = (const char*) p2;

  return *s1 < *s2 ? -1 : 1;
}


static int print_file_limits(const char* arg)
{
  assert(sizeof(pid_t) == sizeof(int) || sizeof(pid_t) == sizeof(long int));
  char* endp;
  errno = 0;
  __auto_type pid = strtoul(arg, &endp, 10);
  if (*endp != '\0' || (pid == ULONG_MAX && errno == ERANGE) || (sizeof(pid_t) < sizeof(long int) && pid > INT_MAX)) {
    fprintf(stderr, gettext("invalid PID %s; ignored\n"), arg);
    return 1;
  }

  char buf[PATH_MAX];
  snprintf(buf, sizeof(buf), "/proc/%ld/cmdline", pid);
  int fd = open(buf, O_RDONLY);
  if (fd == -1) {
    error(0, errno, gettext("cannot read command line of process %ld"), pid);
    return 1;
  }

  char buf2[PATH_MAX];
  snprintf(buf, sizeof(buf), "/proc/%ld/exe", pid);
  ssize_t n = readlink(buf, buf2, sizeof(buf2) - 1);
  bool skip = true;
  if (n > 0)
    buf2[n] = '\0';
  else {
    buf2[0] = '\0';
    skip = false;
  }

  printf("%ld:\t%s", pid, buf2);
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
  close(fd);

  puts(gettext("\n\
   resource               current         maximum"));

  /* Retrieve all limits.  */
  for (__typeof__(nlimits) i = 0; i < nlimits; ++i) {
    struct rlimit64 lim;
    if (prlimit64(pid, limits[i].limit, NULL, &lim) != 0) {
      fprintf(stderr, gettext("\
cannot retrieve limit %s for process %ld: %m\n"), limits[i].name, pid);
      if (errno == EPERM)
        return 1;
    }

    char* wp = stpcpy(buf, limits[i].name);
    enum unit unit = limits[i].unit;
    unsigned int scale = 1;
    if (unit != unit_none) {
      const char *unitstr = unit_strings[unit];
      if (output_mode != unit_none)
        switch (unit) {
        case unit_blocks:
          unitstr = unit_strings[output_mode];
          scale = output_mode == unit_kbytes ? 2 : 2048;
          break;
        case unit_bytes:
          unitstr = unit_strings[output_mode];
          scale = output_mode == unit_kbytes ? 1024 : 1048576;
          break;
        case unit_kbytes:
          unitstr = unit_strings[output_mode];
          scale = output_mode == unit_kbytes ? 1 : 1024;
          break;
        default:
          break;
        }

      snprintf(wp, sizeof(buf) - (wp - buf), "(%s)", unitstr);
    }

    printf("  %-20s ", buf);

    if (lim.rlim_cur == RLIM64_INFINITY)
      printf("  unlimited     ");
    else
      printf("  %-14llu", (unsigned long long int) lim.rlim_cur / scale);

    if (lim.rlim_max == RLIM64_INFINITY)
      printf("  unlimited\n");
    else
      printf("  %llu\n", (unsigned long long int) lim.rlim_max / scale);
  }

  return 0;
}
