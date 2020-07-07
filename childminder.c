/* childminder.c
 *
 * Gary Polhill, 6 July 2020
 *
 * C program to watch a child you want to run and to get as much information
 * as it can from the signals it gets about the child. This is weaker than 
 * nanny (if it worked), but doesn't rely on ptrace.
 *
 * Copyright (C) 2020  The James Hutton Institute
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <pwd.h>
#include <uuid/uuid.h>

/* typedefs
 */

typedef enum check_signal_status {
  SIG_CK_NOK, SIG_CK_BLK, SIG_CK_NASK, SIG_CK_IGN, SIG_CK_DFL, SIG_CK_NDFL
} sig_ck_t;

/* macros
 */

#define DEFAULT_LOG_DIR "log"
#define SIG_END_ARR 0
#define CONTINUE_STOPPED 0
#define RESTART_STOPPED -1
#define RESTART_SIGNALED -2
#define NOHANG_SLEEP_NSEC 1000000L

/* procedure declarations
 */

void start_child(void);
void wait_for_child(int secs, void(*func)(void));
const char *signalstr(int sig);
void log_user(uid_t u);
void log_timestamp(void);
void sig_handler(int signo, siginfo_t *info, void *context);
int *trap_everything(void(*handler)(int, siginfo_t *, void *), int *no_block);
FILE *open_log(const char *log_dir, const char *cmd);
void init_signal_arrays(void);
int check_signal_nok(int sig);
sig_ck_t check_signal(int sig);
char *gethostnamenicely(const char *def);
void math_log_func(void);
void math_double_func(void);
void string_func(void);
void file_func(void);
void memory_func(void);
void random_func(void);


/* globals
 */

FILE *log_fp = NULL;
int *signos;
const char **sigstrs;
int n_sigs = -1;
pid_t pid;
pid_t child_pid;
char *hostname;
char * const *cmd_argv;
int cmd_argc;

/* array of all the signals this system responds to, some of which might
 * be aliases for each other
 */

int all_signos[] = {
#ifdef SIGABRT
  SIGABRT,
#endif
#ifdef SIGALRM
  SIGALRM,
#endif
#ifdef SIGBUS
  SIGBUS,
#endif
#ifdef SIGCHLD
  SIGCHLD,
#endif
#ifdef SIGCONT
  SIGCONT,
#endif
#ifdef SIGFPE
  SIGFPE,
#endif
#ifdef SIGHUP
  SIGHUP,
#endif
#ifdef SIGILL
  SIGILL,
#endif
#ifdef SIGINT
  SIGINT,
#endif
#ifdef SIGKILL
  SIGKILL,
#endif
#ifdef SIGPIPE
  SIGPIPE,
#endif
#ifdef SIGPOLL
  SIGPOLL,
#endif
#ifdef SIGPROF
  SIGPROF,
#endif
#ifdef SIGQUIT
  SIGQUIT,
#endif
#ifdef SIGSEGV
  SIGSEGV,
#endif
#ifdef SIGSTOP
  SIGSTOP,
#endif
#ifdef SIGSYS
  SIGSYS,
#endif
#ifdef SIGTERM
  SIGTERM,
#endif
#ifdef SIGTRAP
  SIGTRAP,
#endif
#ifdef SIGTSTP
  SIGTSTP,
#endif
#ifdef SIGTTIN
  SIGTTIN,
#endif
#ifdef SIGTTOU
  SIGTTOU,
#endif
#ifdef SIGUSR1
  SIGUSR1,
#endif
#ifdef SIGUSR2
  SIGUSR2,
#endif
#ifdef SIGURG
  SIGURG,
#endif
#ifdef SIGVTALRM
  SIGVTALRM,
#endif
#ifdef SIGXCPU
  SIGXCPU,
#endif
#ifdef SIGXFSZ
  SIGXFSZ,
#endif
#ifdef SIGWINCH
  SIGWINCH,
#endif
#ifdef SIGEMT
  SIGEMT,
#endif
#ifdef SIGINFO
  SIGINFO,
#endif
#ifdef SIGPWR
  SIGPWR,
#endif
#ifdef SIGLOST
  SIGLOST,
#endif
#ifdef SIGSTKFLT
  SIGSTKFLT,
#endif
#ifdef SIGUNUSED
  SIGUNUSED,
#endif
#ifdef SIGCLD
  SIGCLD,
#endif
  SIG_END_ARR
};
  
const char *all_sigstrs[] = {
#ifdef SIGABRT
  "SIGABRT",
#endif
#ifdef SIGALRM
  "SIGALRM",
#endif
#ifdef SIGBUS
  "SIGBUS",
#endif
#ifdef SIGCHLD
  "SIGCHLD",
#endif
#ifdef SIGCONT
  "SIGCONT",
#endif
#ifdef SIGFPE
  "SIGFPE",
#endif
#ifdef SIGHUP
  "SIGHUP",
#endif
#ifdef SIGILL
  "SIGILL",
#endif
#ifdef SIGINT
  "SIGINT",
#endif
#ifdef SIGKILL
  "SIGKILL",
#endif
#ifdef SIGPIPE
  "SIGPIPE",
#endif
#ifdef SIGPOLL
  "SIGPOLL",
#endif
#ifdef SIGPROF
  "SIGPROF",
#endif
#ifdef SIGQUIT
  "SIGQUIT",
#endif
#ifdef SIGSEGV
  "SIGSEGV",
#endif
#ifdef SIGSTOP
  "SIGSTOP",
#endif
#ifdef SIGSYS
  "SIGSYS",
#endif
#ifdef SIGTERM
  "SIGTERM",
#endif
#ifdef SIGTRAP
  "SIGTRAP",
#endif
#ifdef SIGTSTP
  "SIGTSTP",
#endif
#ifdef SIGTTIN
  "SIGTTIN",
#endif
#ifdef SIGTTOU
  "SIGTTOU",
#endif
#ifdef SIGUSR1
  "SIGUSR1",
#endif
#ifdef SIGUSR2
  "SIGUSR2",
#endif
#ifdef SIGURG
  "SIGURG",
#endif
#ifdef SIGVTALRM
  "SIGVTALRM",
#endif
#ifdef SIGXCPU
  "SIGXCPU",
#endif
#ifdef SIGXFSZ
  "SIGXFSZ",
#endif
#ifdef SIGWINCH
  "SIGWINCH",
#endif
#ifdef SIGEMT
  "SIGEMT",
#endif
#ifdef SIGINFO
  "SIGINFO",
#endif
#ifdef SIGPWR
  "SIGPWR",
#endif
#ifdef SIGLOST
  "SIGLOST",
#endif
#ifdef SIGSTKFLT
  "SIGSTKFLT",
#endif
#ifdef SIGUNUSED
  "SIGUNUSED",
#endif
#ifdef SIGCLD
  "SIGCLD",
#endif
  (const char *)SIG_END_ARR
};

/* main()
 *
 * Process command line options and get things going
 */

int main(int argc, char * const argv[]) {
  int i;
  const char *log_dir;

  pid = getpid();
  hostname = gethostnamenicely("_host-unknown_");
  
  /* process command-line arguments
   */

  log_dir = DEFAULT_LOG_DIR;
  i = 1;
  while(i < argc && argv[i][0] == '-') {
    const char *opt;

    opt = argv[i];

    i++;

    if(strcmp(opt, "--") == 0) {
      break;			/* explicit end of command-line
				 * options */
    }
    else if(strcmp(opt, "-w") == 0 || strcmp(opt, "--working-directory") == 0) {
				/* change working directory */
      if(chdir(argv[i]) == -1) {
	perror(argv[i]);
	exit(1);
      }
      i++;
    }
    else if(strcmp(opt, "-l") == 0 || strcmp(opt, "--log-directory") == 0) {
				/* specify logging directory */
      log_dir = argv[i];
      i++;
    }
    else {
      fprintf(stderr, "Option %s not recognized\n", opt);
      return 1;
    }
  }
  
  cmd_argv = &(argv[i]);
  cmd_argc = argc - i;

  init_signal_arrays();
  log_fp = open_log(log_dir, cmd_argv[0]);

  start_child();
    
  /* parent */
  trap_everything(sig_handler, NULL);
  wait_for_child(0, NULL);
  
  if(log_fp != stdout && log_fp != stderr) {
    fclose(log_fp);
  }
  free(signos);
  free(sigstrs);
  free(hostname);

  return 0;
}

/* start_child()
 *
 * Kick off the child process
 */

void start_child(void) {
  child_pid = fork();
  if(child_pid == 0) {		/* child */
    execvp(cmd_argv[0], cmd_argv);
    perror("execvp failed");
    abort();
  }
  else if(child_pid == -1) {	/* fork failed */
    perror("fork failed");
    abort();
  }
  log_timestamp();
  fprintf(log_fp, "child %s started in process %d\n", cmd_argv[0], child_pid);
}

/* wait_for_child()
 *
 * Wait for the child process -- it should return when the child has been
 * detected as being OK. The argument is positive if there is no child
 * process at all, but some number of seconds to continue running for
 * after which to stop -- during that time a function can be called, which is
 * the non-null second argument, otherwise sleep. If secs is negative, then
 * the process will attempt to continue a stopped child.
 */

void wait_for_child(int secs, void(*func)(void)) {
  if(secs <= 0) {
    int keepwaiting = 1;

    while(keepwaiting) {
      int status;
      struct timespec sleep_time;
      
      switch(waitpid(child_pid, &status, WUNTRACED)) {
      case -1:
	if(errno == ECHILD) {
	  keepwaiting = 0;	/* Child not there any more */
	}
	else if(errno != EINTR) {
	  perror("waitpid");	/* We weren't interrupted by a signal */
	  abort();
	}
	break;
      case 0:			/* Only returned if WNOHANG in third
				 * arg to waitpid() */
	/* A future extension could use this to optionally monitor
	 * 
	 * + Files the child has open (via /proc/child_pid/fd)
	 * + Grandchildren (via /proc/ * /stat ppid %d -- see proc(5))
	 * + Other processes and users that might be affecting this one
	 */
	sleep_time.tv_sec = 0;
	sleep_time.tv_nsec = NOHANG_SLEEP_NSEC;
	nanosleep(&sleep_time, NULL);
	break;
      default:
	if(WIFSTOPPED(status)) {
	  int signum;

	  signum = WSTOPSIG(status);
	  log_timestamp();
	  fprintf(log_fp, "child %d stopped by signal %d (%s)\n", child_pid,
		  signum, signalstr(signum));
#if defined(SIGCONT)
	  /* attempt to continue the stopped child */
	  
	  if(secs < CONTINUE_STOPPED && kill(child_pid, SIGCONT) == -1) {
	    keepwaiting = 0;

	    if(secs < RESTART_STOPPED) {
				/* Restart the child */
	      start_child();
	      log_timestamp();
	      fprintf(log_fp, "restarted child in pid %d\n", child_pid);
	      keepwaiting = 1;
	    }
	  

	  }
	  else {
	    log_timestamp();
	    fprintf(log_fp, "successfully sent child %d SIGCONT\n", child_pid);
	  }
#else
	  keepwaiting = 0;

	  if(secs < RESTART_STOPPED) {
				/* Restart the child */
	    start_child();
	    log_timestamp();
	    fprintf(log_fp, "restarted child in pid %d\n", child_pid);
	    keepwaiting = 1;
	  }

#endif
	}
	else if(WIFEXITED(status)) {
	  log_timestamp();
	  fprintf(log_fp, "child %d exited with status %d\n", child_pid,
		  WEXITSTATUS(status));
	  keepwaiting = 0;
	}
	else if(WIFSIGNALED(status)) {
	  int signum;

	  signum = WTERMSIG(status);
	  log_timestamp();
	  fprintf(log_fp, "child %d terminated by signal %d (%s)\n", child_pid,
		  signum, signalstr(signum));
	  keepwaiting = 0;

	  if(secs < RESTART_SIGNALED) {
				/* Restart the child */
	    start_child();
	    log_timestamp();
	    fprintf(log_fp, "restarted child in pid %d\n", child_pid);
	    keepwaiting = 1;
	  }
	}
#ifdef WCOREDUMP
	else if(WCOREDUMP(status)) {
	  log_timestamp();
	  fprintf(log_fp, "child %d dumped core\n", child_pid);
	  keepwaiting = 0;
	}
#endif
      }
    }
  }
  else {
    if(func == NULL) {
      unsigned sleep_secs;

      sleep_secs = (unsigned)secs;
      while(sleep_secs > 0) {
	sleep_secs = sleep(sleep_secs);
      }
    }
    else {
      struct timeval v_start;
      int time_elapsed;

      if(gettimeofday(&v_start, NULL) == -1) {
	perror("gettimeofday");
	abort();
      }

      time_elapsed = 0;
      do {
	struct timeval v_end;

	func();
	if(gettimeofday(&v_end, NULL) != -1) {
	  if(v_end.tv_sec - v_start.tv_sec > secs
	     || (v_end.tv_sec - v_start.tv_sec == secs
		 && v_end.tv_usec >= v_end.tv_usec)) {
	    time_elapsed = 1;
	  }
	}
      } while(!time_elapsed);
    }
  }
}

/* signalstr()
 *
 * return the signal string for a signal number if known
 */

const char *signalstr(int sig) {
  int i;

  for(i = 0; i < n_sigs; i++) {
    if(signos[i] == sig) {
      return sigstrs[i];
    }
  }
  return "unknown";
}

/* log_process()
 *
 * Print a process ID to the log file. If /proc/PID/cmdline is readable,
 * print the process's command line too.
 */

void log_process(pid_t p) {
  char *proc;
  
  fprintf(log_fp, "%d", (int)p);

  if(asprintf(&proc, "/proc/%d/cmdline", (int)p) > 0) {
    if(access(proc, R_OK) == 0) {
      FILE *fp;

      fp = fopen(proc, "r");
      if(fp != NULL) {
	int c;

	fputc((int)' ', log_fp);
	fputc((int)'(', log_fp);
	while((c = fgetc(fp)) != EOF) {
	  if(fputc(c, log_fp) == EOF) break;
	}
	fputc((int)')', log_fp);
	fclose(fp);
      }
    }
    free(proc);
  }
}

/* log_user()
 *
 * Print a UID to the log file and look up its entry in the passwd file to
 * get and print the login ID if found
 */

void log_user(uid_t u) {
#ifdef _SC_GETPW_R_SIZE_MAX
  int pwsz = (int)sysconf(_SC_GETPW_R_SIZE_MAX);
#else
  int pwsz = 1024;
#endif
  char *buf;
  struct passwd pw, *result = NULL;

  buf = (char *)calloc(pwsz, sizeof(char));
  if(buf == NULL) {
    perror("Allocating buffer for passwd record\n");
    abort();
  }

  if(getpwuid_r(u, &pw, buf, pwsz, &result) == 0 && result != NULL) {
    fprintf(log_fp, "%d (%s)", (int)pw.pw_uid, pw.pw_name);
  }
  else {
    fprintf(log_fp, "%d (unknown user)", (int)u);
  }

  free(buf);
}

/* log_timestamp()
 *
 * Print the timestamp to the log file
 */

void log_timestamp(void) {
  struct timeval v;
  struct tm t;

  if(gettimeofday(&v, NULL) != -1) {
    if(gmtime_r(&(v.tv_sec), &t) != NULL) {
      fprintf(log_fp, "%04d%02d%02dT%02d%02d%02d.%06d ", t.tm_year + 1900,
	      t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec,
	      (int)v.tv_usec);
    }
    else {
      fprintf(log_fp, "????????T??????.%06d ", (int)v.tv_usec);
    }
  }
  else {
    time_t u;

    u = time(NULL);
    if(u != (time_t)-1 && gmtime_r(&u, &t) != NULL) {
      fprintf(log_fp, "%04d%02d%02dT%02d%02d%02d.?????? ", t.tm_year + 1900,
	      t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
    }
    else {
      fprintf(log_fp, "????????T??????.?????? ");
    }
  }
  fprintf(log_fp, "(%s): ", hostname);
}

/* sig_handler()
 *
 * Handle signals
 */

void sig_handler(int signo, siginfo_t *info, void *context) {
  log_timestamp();

  fprintf(log_fp, "signal %d (%s) ", signo, signalstr(signo));

  if(info != NULL) {
    int print_user_and_process = 1;

    /* general si_codes */

    switch(info->si_code) {      
    case SI_USER:
      fprintf(log_fp, "from kill(2)");
      break;
    case SI_QUEUE:
      fprintf(log_fp, "from sigqueue(3)");
      break;
#ifdef SI_KERNEL
    case SI_KERNEL:
      fprintf(log_fp, "from kernel");
      print_user_and_process = 0;
      break;
#endif
    case SI_TIMER:
      fprintf(log_fp, "from POSIX timer expiry");
      print_user_and_process = 0;
      break;
#ifdef SI_TKILL
    case SI_TKILL:
      fprintf(log_fp, "from tkill(2) or tgkill(2)");
      print_user_and_process = 0;
      break;
#endif
    case SI_MESGQ:
      fprintf(log_fp, "from message queue state change (see mq_notify (3))");
      break;
    case SI_ASYNCIO:
      fprintf(log_fp, "from asynchronous I/O completion");
      print_user_and_process = 0;
      break;
    default:
      print_user_and_process = 0;
    }

    /* SIGCHLD si_codes */
    
#if defined(SIGCHLD) || defined(SIGCLD)
    if( 
#  ifdef SIGCHLD
       signo == SIGCHLD
#  else
       signo == SIGCLD
#  endif
       ) {
#  ifndef __APPLE__
#    ifdef _SC_CLK_TCK
      long ticks_per_second = sysconf(_SC_CLK_TCK);
      const char *units = "seconds";
#    else
      long ticks_per_second = 1;
      const char *units = "unknown time units";
#    endif
      double ut = (double)info->si_utime / (double)ticks_per_second;
      double st = (double)info->si_stime / (double)ticks_per_second;
#  endif

      switch(info->si_code) {
      case CLD_EXITED:
	fprintf(log_fp, "from child exiting");
	break;
      case CLD_KILLED:
	fprintf(log_fp, "from child dumping core");
	break;
      case CLD_STOPPED:
	fprintf(log_fp, "from child stopping");
	break;
      case CLD_CONTINUED:
	fprintf(log_fp, "from child continuing");
	break;
      }

#  ifndef __APPLE__
      fprintf(log_fp, " child user CPU time %g %s; system CPU time %g %s",
	      ut, units, st, units);
#  endif
      fprintf(log_fp, " child status 0x%0*x", (int)(sizeof(int) * 2),
	      info->si_status);
      print_user_and_process = 1;
    }
#endif


    /* SIGILL si_codes */
    
#ifdef SIGILL
    if(signo == SIGILL) {
      switch(info->si_code) {
      case ILL_ILLOPC:
	fprintf(log_fp, " (illegal opcode)");
	break;
      case ILL_ILLOPN:
	fprintf(log_fp, " (illegal operand)");
	break;
      case ILL_ILLADR:
	fprintf(log_fp, " (illegal addressing mode)");
	break;
      case ILL_ILLTRP:
	fprintf(log_fp, " (illegal trap)");
	break;
      case ILL_PRVOPC:
	fprintf(log_fp, " (privileged opcode)");
	break;
      case ILL_PRVREG:
	fprintf(log_fp, " (privileged register)");
	break;
      case ILL_COPROC:
	fprintf(log_fp, " (coprocessor error)");
	break;
      case ILL_BADSTK:
	fprintf(log_fp, " (internal stack error)");
	break;
      }
    }
#endif

    /* SIGFPE si_codes */

#ifdef SIGFPE
    if(signo == SIGFPE) {
      switch(info->si_code) {
      case FPE_INTDIV:
	fprintf(log_fp, " (integer divide by zero)");
	break;
      case FPE_INTOVF:
	fprintf(log_fp, " (integer overflow)");
	break;
      case FPE_FLTDIV:
	fprintf(log_fp, " (floating-point divide by zero)");
	break;
      case FPE_FLTOVF:
	fprintf(log_fp, " (floating-point overflow)");
	break;
      case FPE_FLTUND:
	fprintf(log_fp, " (floating-point underflow)");
	break;
      case FPE_FLTRES:
	fprintf(log_fp, " (floating-point inexact result)");
	break;
      case FPE_FLTINV:
	fprintf(log_fp, " (floating-point invalid operation)");
	print_user_and_process = 0;
	break;
      case FPE_FLTSUB:
	fprintf(log_fp, " (floating-point subscript out of range)");
	print_user_and_process = 0;
	break;
      }
    }
#endif

    
    /* SIGSEGV si_codes */

#ifdef SIGSEGV
    if(signo == SIGSEGV) {
      switch(info->si_code) {
      case SEGV_MAPERR:
	fprintf(log_fp, " (address not mapped to object)");
	break;
      case SEGV_ACCERR:
	fprintf(log_fp, " (invalid permissions for mapped object)");
	break;
#  ifdef SEGV_BNDERR
      case SEGV_BNDERR:
	fprintf(log_fp, " (failed address bound checks)");
	break;
#  endif
#  ifdef SEGV_PKUERR
      case SEGV_PKUERR:
	fprintf(log_fp,
		" (access denied by memory protection keys -- see pkeys(7))");
	break;
#  endif
      }
    }
#endif
    
      /* SIGBUS si_codes */

#ifdef SIGBUS
    if(signo == SIGBUS) {
      switch(info->si_code) {
      case BUS_ADRALN:
	fprintf(log_fp, " (invalid address alignment)");
	break;
      case BUS_ADRERR:
	fprintf(log_fp, " (nonexistent physical address)");
	break;
      case BUS_OBJERR:
	fprintf(log_fp, " (object-specific hardware error)");
	break;
#  ifdef BUS_MCEERR_AR
      case BUS_MCEERR_AR:
	fprintf(log_fp, " (hardware memory error -- action required");
	break;
#  endif
#  ifdef BUS_MCEERR_AO
      case BUS_MCEERR_AO:
	fprintf(log_fp, " (hardware memory error -- action optional)");
	break;
#  endif
      }
    }
#endif
    
    /* SIGIO si_codes */

#if defined(SIGIO) || defined(SIGPOLL)
    if(
#  ifdef SIGIO
       signo == SIGIO
#  else
       signo == SIGPOLL
#  endif
       ) {
#  ifndef __APPLE__
#    if defined(MAXPATHLEN)
      int psz = MAXPATHLEN;
      char path[MAXPATHLEN];
#    elif defined(PATH_MAX)
      int psz = PATH_MAX;
      char path[PATH_MAX];
#    else
      int psz = 4096;
      char path[4096];
#    endif
      char *buf;
#  endif
      
      switch(info->si_code) {
      case POLL_IN:
	fprintf(log_fp, " (data input available)");
	print_user_and_process = 0;
	break;
      case POLL_OUT:
	fprintf(log_fp, " (output buffers available)");
	print_user_and_process = 0;
	break;
      case POLL_MSG:
	fprintf(log_fp, " (input message available)");
	print_user_and_process = 0;
	break;
      case POLL_ERR:
	fprintf(log_fp, " (I/O error)");
	print_user_and_process = 0;
	break;
      case POLL_PRI:
	fprintf(log_fp, " (high priority input available");
	print_user_and_process = 0;
	break;
      case POLL_HUP:
	fprintf(log_fp, " (device disconnected)");
	print_user_and_process = 0;
	break;
      }
      
#  ifndef __APPLE__
      fprintf(log_fp, " on file %d", info->si_fd);

      memset(path, 0, psz);
      
#    ifdef F_GETPATH
      
      if(fcntl(info->si_fd, F_GETPATH, path) != -1) {
	fprintf(log_fp, " (%s)", path);
      }
      
#    else
      
      if(asprintf(&buf, "/proc/self/fd/%d", info->si_fd) > 0) {
	if(readlink(buf, path, psz) != -1) {
	  fprintf(log_fp, " (%s)", path);
	}
	free(buf);
      }
      
#    endif
#  endif
    /* Here we could stop writing to the log file (or trying to) as clearly
     * there is some sort of problem with this process's I/O
     */
    }
#endif

    if(print_user_and_process) {
      fprintf(log_fp, ". Signal sent by user ");
      log_user(info->si_uid);
      fprintf(log_fp, " in process ");
      log_process(info->si_pid);
    }
    else {
      fprintf(log_fp, ". UID (%d) and PID (%d) not populated by default"
	      " and possibly meaningless",
	      info->si_uid, info->si_pid);
    }
  }
  
  /* Could use SIGUSR1/2 to manage things like stopping signal trapping
   * and/or logging; similarly for SIGINT.
   */
#ifdef SIGUSR1
  if(signo == SIGUSR1) {
  }
#endif
#ifdef SIGUSR2
  if(signo == SIGUSR2) {
  }
#endif

  fprintf(log_fp, "\n");
}

/* trap_everything()
 *
 * Set a signal handler for every signal we can, returning an array of length
 * n_sigs with 0 if not trapped, 1 if trapped. Will not attempt to trap
 * SIGKILL or SIGSTOP if these have been defined. Signals not to block
 * apart from SIGKILL or SIGSTOP while running the handler are in the second
 * argument if non-NULL -- the default is to block everything. If non-null,
 * the second argument must end with SIG_END_ARR.
 */

int *trap_everything(void(*handler)(int, siginfo_t *, void *), int *no_block) {
  int *trapped;
  int i;

  trapped = (int *)calloc(n_sigs, sizeof(int));
  if(trapped == NULL) {
    perror("Allocating array of trapped signals");
    abort();
  }

  for(i = 0; i < n_sigs; i++) {
    struct sigaction sig_act;

#ifdef SIGKILL
    if(signos[i] == SIGKILL) continue;
#endif
#ifdef SIGSTOP
    if(signos[i] == SIGSTOP) continue;
#endif
    
    memset(&sig_act, 0, sizeof(struct sigaction));
    sigfillset(&sig_act.sa_mask);
#ifdef SIGKILL
    sigdelset(&sig_act.sa_mask, SIGKILL);
#endif
#ifdef SIGSTOP
    sigdelset(&sig_act.sa_mask, SIGSTOP);
#endif

    if(no_block != NULL) {
      int j;

      for(j = 0; no_block[j] != SIG_END_ARR; j++) {
	sigdelset(&sig_act.sa_mask, no_block[j]);
      }
    }

    sig_act.sa_sigaction = handler;
    sig_act.sa_flags = SA_SIGINFO;

    if(sigaction(signos[i], &sig_act, NULL) != -1) {
      trapped[i] = 1;
    }
  }

  return trapped;
}

/* open_log()
 *
 * create a log directory and open a log file there
 */

FILE *open_log(const char *log_dir, const char *cmd) {
  if(strcmp(log_dir, "stderr") == 0) {
    return stderr;
  }
  else if(strcmp(log_dir, "stdout") == 0) {
    return stdout;
  }
  else {
    struct stat log_stat;
    char *log_file = NULL;
    FILE *fp;

    if(stat(log_dir, &log_stat) == -1) {
      if(errno == ENOENT) {
	if(mkdir(log_dir, 0777) == -1) {
	  perror(log_dir);
	  abort();
	}
      }
      else {
	perror(log_dir);
	abort();
      }
    }
    else {
      if((log_stat.st_mode & S_IFDIR) == 0) {
	fprintf(stderr, "Log directory \"%s\" is not a directory\n", log_dir);
	abort();
      }
      if(access(log_dir, R_OK | W_OK | X_OK) == -1) {
	perror(log_dir);
	abort();
      }
    }

    if(asprintf(&log_file, "%s/%s-%s-%06d.txt", log_dir, cmd, hostname, pid)
       < 0) {
      perror("allocating space for log filename");
      abort();
    }

    fp = fopen(log_file, "w");
    if(fp == NULL) {
      perror(log_file);
      abort();
    }
    free(log_file);

    return fp;
  }
}

/* init_signal_arrays()
 *
 * initialize the arrays of signals this system responds to and their strings
 */

void init_signal_arrays(void) {
  int i;
  int j;
  
  n_sigs = 0;
  for(i = 0; all_signos[i] != SIG_END_ARR; i++) {
    if(!check_signal_nok(all_signos[i])) n_sigs++;
  }

  signos = (int *)calloc(n_sigs, sizeof(int));
  if(signos == NULL) {
    perror("Allocating memory for the signos array");
    abort();
  }

  sigstrs = (const char **)calloc(n_sigs, sizeof(const char *));
  if(sigstrs == NULL) {
    perror("Allocating memory for the sigstrs array");
    abort();
  }

  for(i = 0, j = 0; j < n_sigs; i++) {
    if(!check_signal_nok(all_signos[i])) {
      signos[j] = all_signos[i];
      sigstrs[j] = all_sigstrs[i];
      j++;
    }
  }
}

/* check_signal_nok()
 *
 * Return 1 if a signal is not defined on this system, or is already assigned
 * a number that is an alias for another signal, and 0 otherwise.
 */

int check_signal_nok(int sig) {
  int i;

  for(i = 0; i < sig && all_signos[i] != SIG_END_ARR; i++) {
    if(all_signos[i] == sig) {
      return 1;
    }
  }
  return 0;
}

/* check_signal()
 *
 * A signal is SIG_CK_NOK if it is not defined on this system or is assigned
 * a number that is an alias for another signal. It is SIG_CK_NASK if
 * its status can't be queried without error, SIG_CK_BLK if it is already
 * blocked, SIG_CK_IGN if it is currently ignored, SIG_CK_DFL if it is currently
 * assigned a default target, and SIG_CK_NDFL if not ignored or default
 */

sig_ck_t check_signal(int sig) {
  sigset_t blk_mask;
  struct sigaction sig_act;

  if(check_signal_nok(sig)) {
    return SIG_CK_NOK;
  }

  if(sigemptyset(&blk_mask) == -1) {
    perror("emptying block mask signal set");
    abort();
  }
  if(sigprocmask(SIG_SETMASK, NULL, &blk_mask) == -1) {
    perror("getting signal block mask");
    abort();
  }
  if(sigismember(&blk_mask, sig)) {
    return SIG_CK_BLK;
  }

  memset(&sig_act, 0, sizeof(struct sigaction));
  sigemptyset(&sig_act.sa_mask);
  if(sigaction(sig, NULL, &sig_act) == -1) {
    return SIG_CK_NASK;
  }
  else if((void *)(sig_act.sa_sigaction) == (void *)SIG_IGN) {
    return SIG_CK_IGN;
  }
  else if((void *)(sig_act.sa_sigaction) == (void *)SIG_DFL) {
    return SIG_CK_DFL;
  }
  else {
    return SIG_CK_NDFL;
  }
}

/* gethostnamenicely()
 *
 * Return an array allocated with the host name nicely, without having to
 * worry about how long an array to use. The return value should be freed.
 */

char *gethostnamenicely(const char *def) {
  char *name;
  size_t len;

#if defined(_SC_HOST_NAME_MAX) 	/* from unistd.h */

  len = (size_t)sysconf(_SC_HOST_NAME_MAX) + 1;
  name = (char *)calloc(len, sizeof(char));
  if(name == NULL) {
    perror("allocating memory for hostname array");
    abort();
  }
  if(gethostname(name, len) == -1) {
    perror("gethostname");
    strncpy(name, def, len);
  }
  
#else  /* Assume that gethostname returns an error if len isn't long enough */

  errno = 0;
  len = (size_t)1;
  while(errno != EFAULT && errno != EPERM && errno != EACCES
	&& errno != ENOMEM) {
    name = (char *)calloc(len, sizeof(char));
    if(name == NULL) {
      perror("allocating memory for hostname array");
      abort();
    }
    if(gethostname(name, len) != -1 && name[len - 1] == '\0') {
      break;
    }
    len++;
  }
  if(errno == EFAULT || errno == EPERM || errno == EACCES || errno == ENOMEM) {
    perror("gethostname");
    strncpy(name, def, len);
  }
  
#endif

  return name;
}


#define FUNC_ITER_MAX 1000
#define FUNC_TMP_DIR "/var/tmp"

void math_long_func(void) {
  int i;
  long ans;

  ans = 0L;

  for(i = 0; i < FUNC_ITER_MAX; i++) {
    ans++;
    ans = ans ^ (long)i;
    ans <<= i & 15;
    ans *= 19;
  }

  log_timestamp();
  fprintf(log_fp, "answer is %ld\n", ans);
}

void math_double_func(void) {
  int i;
  double ans;

  ans = 0.0;
  for(i = 0; i < FUNC_ITER_MAX; i++) {
    ans += (double)i;
    ans = (i % 2) ? (ans / 3.0) : (ans * 5.0);
  }

  log_timestamp();
  fprintf(log_fp, "answer is %lf\n", ans);
}

void string_func(void) {
  char s[FUNC_ITER_MAX];
  int i;

  for(i = 0; i < FUNC_ITER_MAX; i++) {
    s[i] = '\0' + (char)(i % 126);
    if(i % 101 == 0 || i == FUNC_ITER_MAX) {
      s[i] = '\0';
    }
  }

  for(i = 0; i < FUNC_ITER_MAX - 4; i++) {
    if(strcmp(&(s[i]), "abc") <= 0) {
      strcpy(&(s[i]), "abc");
    }
  }

  log_timestamp();
  fprintf(log_fp, "answer is %s", s);
}

void file_func(void) {
  int i;
  int ones = 0;

  for(i = 0; i < FUNC_ITER_MAX; i++) {
    char *filename;

    if(asprintf(&filename, "%s/file-%d.txt", FUNC_TMP_DIR, i) >= 0) {
      FILE *fp;

      fp = fopen(filename, "w");
      if(fp != NULL) {
	int j;

	for(j = 2; j <= i + 2; j++) {
	  fprintf(fp, "%d\n", i % j);
	}
	fclose(fp);

	fp = fopen(filename, "r");

	if(fp != NULL) {
	  while(!feof(fp)) {
	    if(fgetc(fp) == (int)'1') ones++;
	  }
	  fclose(fp);
	}

	unlink(filename);
      }
      
      free(filename);
    }
  }
  log_timestamp();
  fprintf(log_fp, "answer is %d\n", ones);
}

void memory_func(void) {
  int i;
  int ans;

  ans = 0;
  for(i = 1; i <= FUNC_ITER_MAX; i++) {
    int *a;

    a = (int *)calloc(i * 1024, sizeof(int));
    if(a != NULL) {
      int j;

      for(j = 0; j < i * 1024; j++) {
	a[j] = j % i;
      }

      ans += a[i];

      free(a);
    }
  }
  log_timestamp();
  fprintf(log_fp, "answer is %d\n", ans);
}

void random_func(void) {
  int r;

  r = rand();

  switch(r % 5) {
  case 0:
    math_long_func();
  case 1:
    math_double_func();
  case 2:
    string_func();
  case 3:
    file_func();
  case 4:
    memory_func();
  }
}