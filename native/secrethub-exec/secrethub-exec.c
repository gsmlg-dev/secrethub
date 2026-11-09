/*
 * secrethub-exec - resolve credentials into the environment, then exec.
 *
 * Mode A (resolver):
 *   secrethub-exec --map FILE [--socket PATH] [--replace-env] -- TARGET [ARGS...]
 *   Runs "$SECRETHUB_CLI __exec-resolve --map FILE [--socket PATH]", reads
 *   NAME=VALUE\0 records from a private pipe, applies them and execvp()s
 *   TARGET in place of this process.
 *
 * Mode B (systemd credentials directory):
 *   secrethub-exec --credential NAME[=ENVVAR] ... [--replace-env] -- TARGET [ARGS...]
 *   Validates $CREDENTIALS_DIRECTORY/NAME (regular, non-empty, <= 1 MiB) and
 *   optionally exports its exact bytes as ENVVAR.
 *
 * Credential values and the constructed environment are never printed.
 */
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/prctl.h>
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define PROG "secrethub-exec"
#define MAX_OUTPUT ((size_t)1048576)
#define MAX_NAME 255

#define EXIT_FAIL 1
#define EXIT_USAGE 2

extern char **environ;

/* ------------------------------------------------------------------ */
/* helpers                                                             */

static void wipe(void *p, size_t n) {
  volatile unsigned char *v = (volatile unsigned char *)p;
  while (n--) *v++ = 0;
}

static void die(int code, const char *fmt, const char *arg) {
  fputs(PROG ": ", stderr);
  if (arg)
    fprintf(stderr, fmt, arg);
  else
    fputs(fmt, stderr);
  fputc('\n', stderr);
  exit(code);
}

static void usage(const char *msg, const char *arg) { die(EXIT_USAGE, msg, arg); }

static int is_env_name(const char *s, size_t len) {
  size_t i;
  if (len == 0 || len > MAX_NAME) return 0;
  if (!((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z') || s[0] == '_'))
    return 0;
  for (i = 1; i < len; i++) {
    char c = s[i];
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
          c == '_'))
      return 0;
  }
  return 1;
}

static int is_cred_name(const char *s, size_t len) {
  size_t i;
  if (len == 0 || len > MAX_NAME) return 0;
  if (strcmp(s, ".") == 0 || strcmp(s, "..") == 0) return 0;
  for (i = 0; i < len; i++) {
    char c = s[i];
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
          c == '_' || c == '.' || c == '-'))
      return 0;
  }
  return 1;
}

static void exec_target(char **argv) {
  int err;
  execvp(argv[0], argv);
  err = errno;
  fprintf(stderr, PROG ": cannot execute %s: %s\n", argv[0], strerror(err));
  exit(err == EACCES ? 126 : 127);
}

/* ------------------------------------------------------------------ */
/* Mode A: resolver                                                    */

static const int fwd_signals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT};
#define N_FWD (sizeof(fwd_signals) / sizeof(fwd_signals[0]))

static volatile sig_atomic_t g_child = 0;
static volatile sig_atomic_t g_signal = 0;

static void forward_handler(int sig) {
  int saved = errno;
  if (g_signal == 0) g_signal = sig;
  if (g_child > 0) kill((pid_t)g_child, sig);
  errno = saved;
}

static void die_by_signal(int sig) {
  struct sigaction sa;
  sigset_t set;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_DFL;
  sigemptyset(&sa.sa_mask);
  sigaction(sig, &sa, NULL);
  sigemptyset(&set);
  sigaddset(&set, sig);
  sigprocmask(SIG_UNBLOCK, &set, NULL);
  raise(sig);
  _exit(128 + sig);
}

static void run_resolver(const char *map, const char *socket_path, int replace_env,
                         char **target) {
  const char *cli = getenv("SECRETHUB_CLI");
  char *rargv[7];
  int rargc = 0;
  int pfd[2];
  struct sigaction sa, old[N_FWD];
  int installed[N_FWD];
  sigset_t block, oldmask;
  pid_t pid, parent;
  unsigned char *buf;
  size_t len = 0;
  int overflow = 0, status = 0, read_err = 0;
  size_t i, nrec, k;
  char **names, **values;

  if (cli == NULL || cli[0] == '\0') usage("SECRETHUB_CLI is not set", NULL);

  rargv[rargc++] = (char *)cli;
  rargv[rargc++] = "__exec-resolve";
  rargv[rargc++] = "--map";
  rargv[rargc++] = (char *)map;
  if (socket_path) {
    rargv[rargc++] = "--socket";
    rargv[rargc++] = (char *)socket_path;
  }
  rargv[rargc] = NULL;

  buf = malloc(MAX_OUTPUT + 1);
  if (buf == NULL) die(EXIT_FAIL, "out of memory", NULL);

  if (pipe(pfd) != 0) die(EXIT_FAIL, "pipe: %s", strerror(errno));
  fcntl(pfd[0], F_SETFD, FD_CLOEXEC);
  fcntl(pfd[1], F_SETFD, FD_CLOEXEC);

  /* Install forwarding handlers (no SA_RESTART so reads see EINTR).
   * Signals ignored on entry stay ignored. */
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = forward_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigemptyset(&block);
  for (i = 0; i < N_FWD; i++) {
    installed[i] = 0;
    sigaction(fwd_signals[i], NULL, &old[i]);
    if (old[i].sa_handler == SIG_IGN) continue;
    sigaddset(&block, fwd_signals[i]);
    if (sigaction(fwd_signals[i], &sa, NULL) == 0) installed[i] = 1;
  }

  /* Block forwarded signals across fork so g_child is set before delivery. */
  sigprocmask(SIG_BLOCK, &block, &oldmask);
  parent = getpid();
  pid = fork();
  if (pid < 0) {
    int err = errno;
    sigprocmask(SIG_SETMASK, &oldmask, NULL);
    die(EXIT_FAIL, "fork: %s", strerror(err));
  }
  if (pid == 0) {
    int devnull;
    for (i = 0; i < N_FWD; i++)
      if (installed[i]) sigaction(fwd_signals[i], &old[i], NULL);
    sigprocmask(SIG_SETMASK, &oldmask, NULL);
#ifdef __linux__
    prctl(PR_SET_PDEATHSIG, SIGTERM);
#endif
    if (getppid() != parent) _exit(EXIT_FAIL);
    devnull = open("/dev/null", O_RDONLY);
    if (devnull < 0 || dup2(devnull, STDIN_FILENO) < 0) _exit(EXIT_FAIL);
    if (devnull != STDIN_FILENO) close(devnull);
    if (dup2(pfd[1], STDOUT_FILENO) < 0) _exit(EXIT_FAIL);
    execv(cli, rargv);
    fprintf(stderr, PROG ": cannot execute resolver %s: %s\n", cli, strerror(errno));
    _exit(EXIT_FAIL);
  }
  g_child = pid;
  sigprocmask(SIG_SETMASK, &oldmask, NULL);
  close(pfd[1]);

  for (;;) {
    ssize_t n;
    if (len > MAX_OUTPUT) {
      overflow = 1;
      break;
    }
    n = read(pfd[0], buf + len, MAX_OUTPUT + 1 - len);
    if (n > 0) {
      len += (size_t)n;
    } else if (n == 0) {
      break;
    } else if (errno == EINTR) {
      continue;
    } else {
      read_err = errno;
      break;
    }
  }
  if (overflow || read_err) kill(pid, SIGTERM);
  close(pfd[0]);

  while (waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR) {
      status = -1;
      break;
    }
  }
  g_child = 0;

  if (g_signal != 0) {
    wipe(buf, len);
    die_by_signal(g_signal);
  }
  for (i = 0; i < N_FWD; i++)
    if (installed[i]) sigaction(fwd_signals[i], &old[i], NULL);

  if (overflow) {
    wipe(buf, len);
    die(EXIT_FAIL, "resolver output exceeds 1 MiB limit", NULL);
  }
  if (read_err) {
    wipe(buf, len);
    die(EXIT_FAIL, "reading resolver output: %s", strerror(read_err));
  }
  if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    wipe(buf, len);
    die(EXIT_FAIL, "credential resolution failed", NULL);
  }

  /* Parse NAME=VALUE\0 records. */
  if (len > 0 && buf[len - 1] != '\0') {
    wipe(buf, len);
    die(EXIT_FAIL, "malformed resolver output: unterminated record", NULL);
  }
  nrec = 0;
  for (i = 0; i < len; i++)
    if (buf[i] == '\0') nrec++;
  names = calloc(nrec + 1, sizeof(char *));
  values = calloc(nrec + 1, sizeof(char *));
  if (names == NULL || values == NULL) {
    wipe(buf, len);
    die(EXIT_FAIL, "out of memory", NULL);
  }

  {
    size_t off = 0;
    for (k = 0; k < nrec; k++) {
      char *rec = (char *)buf + off;
      size_t rlen = strlen(rec);
      char *eq = memchr(rec, '=', rlen);
      size_t nlen;
      size_t j;
      off += rlen + 1;
      if (eq == NULL) {
        wipe(buf, len);
        die(EXIT_FAIL, "malformed resolver output: record without '='", NULL);
      }
      nlen = (size_t)(eq - rec);
      if (!is_env_name(rec, nlen)) {
        wipe(buf, len);
        die(EXIT_FAIL, "malformed resolver output: invalid variable name", NULL);
      }
      *eq = '\0';
      names[k] = rec;
      values[k] = eq + 1;
      for (j = 0; j < k; j++) {
        if (strcmp(names[j], rec) == 0) {
          fprintf(stderr, PROG ": duplicate variable %s in resolver output\n", rec);
          wipe(buf, len);
          exit(EXIT_FAIL);
        }
      }
      if (!replace_env && getenv(rec) != NULL) {
        fprintf(stderr,
                PROG ": variable %s already set in environment (use --replace-env)\n", rec);
        wipe(buf, len);
        exit(EXIT_FAIL);
      }
    }
  }

  for (k = 0; k < nrec; k++) {
    if (setenv(names[k], values[k], 1) != 0) {
      fprintf(stderr, PROG ": cannot set %s: %s\n", names[k], strerror(errno));
      wipe(buf, len);
      exit(EXIT_FAIL);
    }
  }
  wipe(buf, len);
  free(buf);
  free(names);
  free(values);

  exec_target(target);
}

/* ------------------------------------------------------------------ */
/* Mode B: systemd credentials directory                               */

struct cred {
  char *name;   /* credential file name */
  char *envvar; /* NULL when validate-only */
  char *value;  /* NUL-terminated content when exported */
  size_t len;
};

static void load_credential(const char *dir, struct cred *c) {
  size_t plen = strlen(dir) + 1 + strlen(c->name) + 1;
  char *path = malloc(plen);
  struct stat st;
  int fd;
  char *data;
  size_t len = 0;

  if (path == NULL) die(EXIT_FAIL, "out of memory", NULL);
  snprintf(path, plen, "%s/%s", dir, c->name);
  fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  free(path);
  if (fd < 0) {
    fprintf(stderr, PROG ": credential %s: %s\n", c->name, strerror(errno));
    exit(EXIT_FAIL);
  }
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
    die(EXIT_FAIL, "credential %s is not a regular file", c->name);
  if (st.st_size <= 0) die(EXIT_FAIL, "credential %s is empty", c->name);
  if ((unsigned long long)st.st_size > MAX_OUTPUT)
    die(EXIT_FAIL, "credential %s exceeds 1 MiB limit", c->name);

  data = malloc(MAX_OUTPUT + 2);
  if (data == NULL) die(EXIT_FAIL, "out of memory", NULL);
  for (;;) {
    ssize_t n = read(fd, data + len, MAX_OUTPUT + 1 - len);
    if (n > 0) {
      len += (size_t)n;
      if (len > MAX_OUTPUT) break;
    } else if (n == 0) {
      break;
    } else if (errno != EINTR) {
      int err = errno;
      wipe(data, len);
      fprintf(stderr, PROG ": credential %s: %s\n", c->name, strerror(err));
      exit(EXIT_FAIL);
    }
  }
  close(fd);
  if (len == 0) die(EXIT_FAIL, "credential %s is empty", c->name);
  if (len > MAX_OUTPUT) {
    wipe(data, len);
    die(EXIT_FAIL, "credential %s exceeds 1 MiB limit", c->name);
  }
  if (c->envvar == NULL) {
    wipe(data, len);
    free(data);
    return;
  }
  if (memchr(data, '\0', len) != NULL) {
    wipe(data, len);
    die(EXIT_FAIL, "credential %s contains NUL and cannot be exported", c->name);
  }
  data[len] = '\0';
  c->value = data;
  c->len = len;
}

static void run_credentials(struct cred *creds, size_t ncreds, int replace_env,
                            char **target) {
  const char *dir = getenv("CREDENTIALS_DIRECTORY");
  size_t i, j;

  if (dir == NULL || dir[0] != '/')
    die(EXIT_FAIL, "CREDENTIALS_DIRECTORY is not set to an absolute path", NULL);

  for (i = 0; i < ncreds; i++) {
    if (creds[i].envvar == NULL) continue;
    for (j = 0; j < i; j++)
      if (creds[j].envvar && strcmp(creds[j].envvar, creds[i].envvar) == 0)
        die(EXIT_FAIL, "duplicate environment variable %s", creds[i].envvar);
    if (!replace_env && getenv(creds[i].envvar) != NULL) {
      fprintf(stderr, PROG ": variable %s already set in environment (use --replace-env)\n",
              creds[i].envvar);
      exit(EXIT_FAIL);
    }
  }

  for (i = 0; i < ncreds; i++) load_credential(dir, &creds[i]);

  for (i = 0; i < ncreds; i++) {
    if (creds[i].envvar == NULL) continue;
    if (setenv(creds[i].envvar, creds[i].value, 1) != 0) {
      fprintf(stderr, PROG ": cannot set %s: %s\n", creds[i].envvar, strerror(errno));
      exit(EXIT_FAIL);
    }
    wipe(creds[i].value, creds[i].len);
    free(creds[i].value);
    creds[i].value = NULL;
  }

  exec_target(target);
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
  int sep = -1, i;
  const char *map = NULL, *socket_path = NULL;
  int replace_env = 0;
  struct cred *creds;
  size_t ncreds = 0;

  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--") == 0) {
      sep = i;
      break;
    }
  }
  if (sep < 0) usage("usage: missing '--' before target command", NULL);
  if (sep + 1 >= argc) usage("usage: missing target command after '--'", NULL);

  creds = calloc((size_t)argc, sizeof(struct cred));
  if (creds == NULL) die(EXIT_FAIL, "out of memory", NULL);

  for (i = 1; i < sep; i++) {
    const char *a = argv[i];
    if (strcmp(a, "--map") == 0 || strcmp(a, "--socket") == 0 ||
        strcmp(a, "--credential") == 0) {
      if (i + 1 >= sep) usage("usage: option %s requires an argument", a);
      if (strcmp(a, "--map") == 0) {
        if (map) usage("usage: --map given more than once", NULL);
        map = argv[++i];
        if (map[0] == '\0') usage("usage: --map requires a non-empty path", NULL);
      } else if (strcmp(a, "--socket") == 0) {
        if (socket_path) usage("usage: --socket given more than once", NULL);
        socket_path = argv[++i];
        if (socket_path[0] == '\0') usage("usage: --socket requires a non-empty path", NULL);
      } else {
        char *spec = argv[++i];
        char *eq = strchr(spec, '=');
        struct cred *c = &creds[ncreds++];
        if (eq) {
          *eq = '\0';
          c->envvar = eq + 1;
          if (!is_env_name(c->envvar, strlen(c->envvar)))
            usage("usage: invalid environment variable name in --credential %s", spec);
        }
        c->name = spec;
        if (!is_cred_name(spec, strlen(spec)))
          usage("usage: invalid credential name in --credential", NULL);
      }
    } else if (strcmp(a, "--replace-env") == 0) {
      replace_env = 1;
    } else {
      usage("usage: unknown option %s", a);
    }
  }

  if ((map || socket_path) && ncreds > 0)
    usage("usage: --map/--socket cannot be combined with --credential", NULL);
  if (socket_path && !map) usage("usage: --socket requires --map", NULL);
  if (!map && ncreds == 0) usage("usage: one of --map or --credential is required", NULL);

  if (map) run_resolver(map, socket_path, replace_env, &argv[sep + 1]);
  run_credentials(creds, ncreds, replace_env, &argv[sep + 1]);
  return EXIT_FAIL; /* not reached */
}
