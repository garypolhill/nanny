/* nanny.c
 *
 * Gary Polhill, 28 November 2019
 *
 * C program to 'nanny' a command you want to run and give you information about
 * its termination and any signals it got sent.
 *
 * Copyright (C) 2019  The James Hutton Institute
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

#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/ptrace.h>

void print_timestamp_time(FILE *);
void print_timestamp(FILE *, struct timeval *);
int print_message(FILE *);
void handler(int, siginfo_t *, void *);
void internal_handler(int, siginfo_t *, pid_t, pid_t, const char *);
void new_message(int, const char *, const char *, struct timeval, uid_t,
		 clock_t, clock_t, pid_t, pid_t, pid_t, int, int,
		 const char *);
/* Data types */

typedef struct msgq {
  int signal_number;
  const char *whoami;
  const char *message;
  const char *reason;
  struct timeval signal_time;
  uid_t signal_uid;
  pid_t signal_pid;
  pid_t my_pid;
  pid_t parent_pid;
  clock_t user_time;
  clock_t system_time;
  int child_status;
  int fd;
  struct msgq *tail;
} msgq_t;

/* Globals */

#define HOSTLEN 1024
#define NSIGNALS 31
#define PW_BUFSIZE 2048
#define DEFAULT_LOG_DIR "log"
#define ACT_TERM 1
#define ACT_CORE 3
#define ACT_IGN 2
#define ACT_STOP 5

pid_t pid = (pid_t)-1;
pid_t ppid = (pid_t)-1;
char hostname[HOSTLEN];
int ok = 1;
msgq_t *msg_list = NULL;
msgq_t *next_msg = NULL;
int missed_msg = 0;
int caught_msg = 0;
FILE *output = NULL;

const char *signal_strs[NSIGNALS] = {
  "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT",
  "SIGEMT", "SIGFPE", "SIGKILL", "SIGBUS", "SIGSEGV", "SIGSYS", "SIGPIPE",
  "SIGALRM", "SIGTERM", "SIGURG", "SIGSTOP", "SIGTSTP", "SIGCONT", "SIGCHLD",
  "SIGTTIN", "SIGTTOU", "SIGIO", "SIGXCPU", "SIGXFSZ", "SIGVTALRM", "SIGPROF",
  "SIGWINCH", "SIGINFO", "SIGUSR1", "SIGUSR2"
};
int trapped[NSIGNALS];
int blocked[NSIGNALS];
int signals[NSIGNALS] = {
  SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGABRT,
  SIGEMT, SIGFPE, SIGKILL, SIGBUS, SIGSEGV, SIGSYS, SIGPIPE,
  SIGALRM, SIGTERM, SIGURG, SIGSTOP, SIGTSTP, SIGCONT, SIGCHLD,
  SIGTTIN, SIGTTOU, SIGIO, SIGXCPU, SIGXFSZ, SIGVTALRM, SIGPROF,
  SIGWINCH, SIGINFO, SIGUSR1, SIGUSR2
};
int defacts[NSIGNALS] = {
  ACT_TERM, ACT_TERM, ACT_CORE, ACT_CORE, ACT_CORE, ACT_CORE,
  ACT_CORE, ACT_CORE, ACT_TERM, ACT_CORE, ACT_CORE, ACT_CORE, ACT_TERM,
  ACT_TERM, ACT_TERM, ACT_IGN, ACT_STOP, ACT_STOP, ACT_IGN, ACT_IGN,
  ACT_STOP, ACT_STOP,
#ifdef __APPLE__
                      ACT_IGN, ACT_TERM, ACT_TERM, 
#else
                      ACT_TERM, ACT_CORE, ACT_CORE,
#endif
                                                    ACT_TERM, ACT_TERM,
  ACT_IGN,
#ifdef __APPLE__
           ACT_IGN,
#else
           ACT_TERM,
#endif
                     ACT_TERM, ACT_TERM
}; 
  
/* Main */

int main(int argc, char * const argv[]) {
  pid_t child_pid;
  struct sigaction action;
  struct sigaction old_action;
  sigset_t mask;
  sigset_t old_mask;
  int i;
  const char *cmd;
  char * const *cmd_argv;
  int cmd_argc;
  const char *log_dir = DEFAULT_LOG_DIR;
  struct stat log_stat;
  char *log_file = NULL;

  pid = getpid();
  ppid = getppid();
  if(gethostname(hostname, (size_t)HOSTLEN) == -1) {
    snprintf(hostname, HOSTLEN, "-host unknown %d-", errno);
  }

  /* Process command-line arguments */

  i = 1;
  while(i < argc && argv[i][0] == '-') {
    const char *opt = argv[i];

    i++;
    if(strcmp(opt, "--") == 0) {
      break;
    }
    else if(strcmp(opt, "-wd") == 0) {
      if(chdir(argv[i]) == -1) {
	fprintf(stderr, "Changing working directory to ");
	perror(argv[i]);
	exit(1);
      }
      i++;
    }
    else if(strcmp(opt, "-log") == 0) {
      log_dir = argv[i];
      i++;
    }
  }
  cmd = argv[i];
  cmd_argv = &(argv[i]);
  cmd_argc = argc - i;

  /* Check existence and/or create a log dir */
  
  if(strcmp(log_dir, "stderr") == 0) {
    output = stderr;
  }
  else if(stat(log_dir, &log_stat) == -1) {
    if(errno == ENOENT) {
      if(mkdir(log_dir, 0777) == -1) {
	fprintf(stderr, "Creating log directory ");
	perror(log_dir);
	exit(1);
      }
    }
    else {
      fprintf(stderr, "Checking status of log directory ");
      perror(log_dir);
      exit(1);
    }
  }
  else {			/* stat was successful; log_stat populated */
    if((log_stat.st_mode & S_IFDIR) == 0) {
      fprintf(stderr, "Log directory \"%s\" is not a directory\n", log_dir);
      exit(1);
    }
    if(access(log_dir, R_OK | W_OK | X_OK) == -1) {
      fprintf(stderr, "Checking access to log directory ");
      perror(log_dir);
      exit(1);
    }
  }

  /* Create a log file, defaulting to stderr if there's a problem */

  if(output != stderr &&
     asprintf(&log_file, "%s/%s-%06d.txt", log_dir, hostname, pid) < 0) {
    output = stderr;
  }
  else {
    output = fopen(log_file, "w");
    if(output == NULL) {
      output = stderr;
    }
    free(log_file);
  }

  /* Find out which signals are blocked and trapped */

  if(sigemptyset(&old_mask) == -1) {
    perror("emptying old mask signal set");
    exit(1);
  }
  if(sigemptyset(&mask) == -1) {
    perror("emptying mask signal set");
    exit(1);
  }
  if(sigprocmask(SIG_SETMASK, NULL, &old_mask) == -1) {
    perror("getting signal mask");
    exit(1);
  }
  for(i = 0; i < NSIGNALS; i++) {
    if(sigismember(&old_mask, signals[i])) {
      blocked[i] = 1;
    }
    else {
      blocked[i] = 0;
    }

    memset(&old_action, 0, sizeof(struct sigaction));
    sigemptyset(&old_action.sa_mask);
    if(sigaction(signals[i], NULL, &old_action) == -1) {
      trapped[i] = -1;
    }
    else {
      if((void *)old_action.sa_sigaction == (void *)SIG_IGN) {
	trapped[i] = 0;
      }
      else if((void *)old_action.sa_sigaction == (void *)SIG_DFL) {
	trapped[i] = 1;
      }
      else {
	trapped[i] = 2;
      }
    }
  }

  /* Report on blocked/trapped signals we inherit as a process */

  fprintf(output, "signal status:\n");
  for(i = 0; i < NSIGNALS; i++) {
    fprintf(output, "\t%s [", signal_strs[i]);
    if(blocked[i]) {
      fprintf(output, "blocked (");
    }
    if(trapped[i] == -1) {
      fprintf(output, "error");
    }
    else if(trapped[i] == 0) {
      fprintf(output, "ignored");
    }
    else if(trapped[i] == 1) {
      fprintf(output, "default -- ");
      if(defacts[i] == ACT_TERM) {
	fprintf(output, "terminate");
      }
      else if(defacts[i] == ACT_CORE) {
	fprintf(output, "core dump");
      }
      else if(defacts[i] == ACT_STOP) {
	fprintf(output, "stop");
      }
      else if(defacts[i] == ACT_IGN) {
	fprintf(output, "ignore");
      }
      else {
	fprintf(stderr, "PANIC!");
	abort();
      }
    }
    if(blocked[i]) {
      fprintf(output, ")");
    }
    fprintf(output, "]\n");
  }

  /* Fork and execute the desired command in the child */

  child_pid = fork();
  if(child_pid == 0) {		/* child */
    ppid = pid;
    pid = getpid();
    if(
#if defined(PT_TRACE_ME)
       ptrace(PT_TRACE_ME, (pid_t)0, NULL, 0)
#elif defined(PTRACE_TRACEME)
       ptrace(PTRACE_TRACEME, (pid_t)0, NULL, NULL) 
#else
#  error "No PT_TRACE_ME or PTRACE_TRACEME"
       -1
#endif
       == -1) {
      perror("ptrace failed");
      exit(1);
    }
    print_timestamp_time(output);
    fprintf(output, "child %d executing command cmd %s:", pid, cmd);
    for(i = 0; i < cmd_argc; i++) {
      fprintf(output, " %s", cmd_argv[i]);
    }
    fprintf(output, "\n");
    execvp(cmd, cmd_argv);
    perror("execvp failed");
    exit(1);
  }
  else if(child_pid == -1) {    /* error */
    perror("fork failed");
    exit(1);
  }
  else {			/* parent */
    int status;
    int keepwaiting = 1;

    /* Trap as many signals as we can */

    memset(&action, 0, sizeof(struct sigaction));
    sigemptyset(&action.sa_mask);
    action.sa_sigaction = &handler;
    action.sa_flags = SA_SIGINFO;

    fprintf(output, "parent %d is trapping [", pid);

    for(i = 0; i < NSIGNALS; i++) {
      if(signals[i] == SIGKILL || signals[i] == SIGSTOP
	 || defacts[i] == ACT_IGN) {
	continue;
      }
      if(sigaction(signals[i], &action, NULL) == -1) {
	trapped[i] = 0;
      }
      else {
	trapped[i] = 1;
	fprintf(output, " %s", signal_strs[i]);
      }
    }

    fprintf(output, " ]\n");

    if(
#if defined(PT_ATTACHEXC)
       ptrace(PT_ATTACHEXC, child_pid, NULL, 0)
#elif defined(PT_ATTACH)
       ptrace(PT_ATTACH, child_pid, NULL, 0)
#elif defined(PTRACE_ATTACH)
       ptrace(PTRACE_ATTACH, child_pid, NULL, 0)
#else
#  error "No PT_ATTACHEXEC, PT_ATTACH or PTRACE_ATTACH"
       -1
#endif
       == -1) {
      perror("ptrace attach failed");
      exit(1);
    }
    print_timestamp_time(output);
    fprintf(output, "parent %d successfully attached to child %d\n",
	    pid, child_pid);
    do {
      switch(waitpid(child_pid, &status, WUNTRACED)) {
      case 0:			/* Only returned if WNOHANG in third arg */
	print_timestamp_time(output);
	fprintf(output, "parent %d WNOHANGed from waitpid()\n", pid);
	break;
      case -1:
	perror("waitpid failed");
	exit(1);
      default:
	if(WIFSTOPPED(status)) {
	  int signum;
	  siginfo_t siginfo;

	  signum = WSTOPSIG(status);

#if defined(PTRACE_GETSIGINFO)
	  if(ptrace(PTRACE_GETSIGINFO, child_pid, NULL, &siginfo) != -1) {
	    internal_handler(signum, &siginfo, child_pid, pid, "child");
	  }
	  else {
	    perror("ptrace getsiginfo failed");
	    internal_handler(signum, NULL, child_pid, pid, "child");
	  }
#else
	  /* Macs now seemingly have their own odd system for managing
	   * these things involving EXC_SOFT_SIGNAL or something. A web
	   * page here describes it: https://www.spaceflint.com/?p=150
	   * and if that is appropriately representative of how things are
	   * handled now, it is sufficiently dissimilar from the system on
	   * the service I actually need this program for that I feel
	   * disinclined to implement it
	   */
	  internal_handler(signum, NULL, child_pid, pid, "child");
#endif
	  if(
#if defined(PTRACE_CONT)
	     ptrace(PTRACE_CONT, child_pid, NULL, signum)
#elif defined(PT_CONTINUE)
	     ptrace(PT_CONTINUE, child_pid, (caddr_t)1, signum)
#else
#  error "No PT_CONTINUE or PTRACE_CONT"
             -1
#endif
	     == -1) {
	    perror("ptrace continue failed");
	    exit(1);
	  }
	  
	  caught_msg += print_message(output);
	}
	else if(WIFEXITED(status)) {
	  print_timestamp_time(output);
	  fprintf(output, "child %d exited with status %d\n", child_pid,
		  WEXITSTATUS(status));
	  keepwaiting = 0;
	}
	else if(WIFSIGNALED(status)) {
	  print_timestamp_time(output);
	  fprintf(output, "child %d terminated by signal %s\n", child_pid,
		  strsignal(WTERMSIG(status)));
	  keepwaiting = 0;
	}
#ifdef WCOREDUMP
	else if(WCOREDUMP(status)) {
	  print_timestamp_time(output);
	  fprintf(output, "child %d dumped core\n", child_pid);
	  keepwaiting = 0;
	}
#endif
#ifdef WIFCONTINUED
	else if(WIFCONTINUED(status)) {
	  print_timestamp_time(output);
	  fprintf(output, "child %d continued\n", child_pid);
	}
#endif
      }
    } while(keepwaiting);

    print_timestamp_time(output);
    fprintf(output, "parent %d exiting; %d messages caught, %d messages "
	    "missed\n", pid, caught_msg, missed_msg);
    if(output != stderr) {
      fclose(output);
    }
  }
  return 0;
}

void print_timestamp_time(FILE *fp) {
  struct timeval tm;

  if(gettimeofday(&tm, NULL) != -1) {
    print_timestamp(fp, &tm);
  }
  else {
    fprintf(fp, "........T............. ");
  }
}

void print_timestamp(FILE *fp, struct timeval *tm) {
  struct tm tim;

  if(!(tm->tv_sec == 0 && tm->tv_usec == 0)
     && gmtime_r(&(tm->tv_sec), &tim) != NULL) {
    fprintf(fp, "%04d%02d%02dT%02d%02d%02d.%06d ", tim.tm_year + 1900,
	    tim.tm_mon + 1, tim.tm_mday, tim.tm_hour, tim.tm_min, tim.tm_sec,
	    (int)tm->tv_usec);
  }
  else {
    fprintf(fp, "........T............. ");
  }
}

int print_message(FILE *fp) {
  if(fp == NULL) {
    fp = stdout;
  }
  if(msg_list != NULL) {
    int i;
    msgq_t *tail;

    print_timestamp(fp, &(msg_list->signal_time));
    fprintf(fp, "nanny (%s %d | %d)@%s: ", msg_list->whoami,
	    (int)msg_list->my_pid, (int)msg_list->parent_pid, hostname);
    for(i = 0; i < NSIGNALS; i++) {
      if(signals[i] == msg_list->signal_number) {
	fprintf(fp, "%s (%d) caught ", signal_strs[i], signals[i]);
	break;
      }
    }
    if(i == NSIGNALS) {
      fprintf(fp, "unknown signal (%d) caught ", msg_list->signal_number);
    }
    if(msg_list->signal_uid > (uid_t)0) {
      struct passwd pw, *result = NULL;
      char buf[PW_BUFSIZE];	/* Lazy -- should call sysconf(); except that
				 * on Macs, _SC_GETPW_R_SIZE_MAX is not
				 * defined
				 */

      if(getpwuid_r(msg_list->signal_uid, &pw, buf, PW_BUFSIZE, &result) == 0
	 && result != NULL) {
	fprintf(fp, "from user %s (%d) ", pw.pw_name, (int)pw.pw_uid);
      }
      else {
	fprintf(fp, "from unknown user (%d) ", msg_list->signal_uid);
      }

      if(msg_list->signal_pid > (pid_t)0) {
	fprintf(fp, "running process %d ", (int)msg_list->signal_pid);
      }
    }
    else if(msg_list->signal_pid > (pid_t)0) {
      fprintf(fp, "from process %d ", (int)msg_list->signal_pid);
    }
    if(msg_list->message != NULL) {
      fprintf(fp, "\"%s\" ", msg_list->message);
    }
    else {
      fprintf(fp, "(no message) ");
    }
    if(msg_list->reason != NULL) {
      fprintf(fp, "reason \"%s\"", msg_list->reason);
    }
    else {
      fprintf(fp, "(no reason)");
    }
    if(msg_list->fd != -1) {
      fprintf(fp, " fd %d", msg_list->fd);
    }
    if(msg_list->child_status != 0) {
      fprintf(fp, " child status %d", msg_list->child_status);
    }
#ifndef __APPLE__
    if(msg_list->user_time > (clock_t)0 || msg_list->system_time > (clock_t)0) {
      fprintf(fp, " elapsed user time %ld; elapsed system time %ld",
	      (long)msg_list->user_time, (long)msg_list->system_time);
    }
#endif
    fprintf(fp, "\n");

    tail = msg_list->tail;
    free(msg_list);
    msg_list = tail;

    return 1;
  }
  else {
    return 0;
  }
}

void new_message(int n, const char *msg, const char *reason, struct timeval t,
		 uid_t u, clock_t ut, clock_t st, pid_t sp, pid_t mp, pid_t pp,
		 int fd, int cld, const char *whoami)
{
  msgq_t *new_msg;

  new_msg = malloc(sizeof(msgq_t));
  if(new_msg != NULL) {
    new_msg->signal_number = n;
    new_msg->message = msg;
    new_msg->reason = reason;
    new_msg->signal_time = t;
    new_msg->signal_uid = u;
    new_msg->signal_pid = sp;
    new_msg->user_time = ut;
    new_msg->system_time = st;
    new_msg->my_pid = mp;
    new_msg->parent_pid = pp;
    new_msg->child_status = cld;
    new_msg->fd = fd;
    new_msg->whoami = whoami;
    new_msg->tail = NULL;
    if(next_msg != NULL) {
      next_msg->tail = new_msg;
      next_msg = new_msg;
    }
    if(msg_list == NULL) {
      msg_list = new_msg;
    }
  }
  else {
    missed_msg++;
  }
}

void handler(int signo, siginfo_t *info, void *context) {
  internal_handler(signo, info, pid, ppid, "parent");
}

void internal_handler(int signo, siginfo_t *info, pid_t mypid, pid_t parent,
		      const char *whoami) {
  struct timeval t;
  uid_t u = (uid_t)0;
  pid_t sp = (pid_t)-1;
  const char *msg = NULL;
  const char *reason = NULL;
  int n = signo;
  pid_t mp = mypid;
  pid_t pp = parent;
  clock_t ut = (clock_t)-1;
  clock_t st = (clock_t)-1;
  int status = 0;
  int fd = -1;

  if(gettimeofday(&t, NULL) == -1) {
    t.tv_sec = 0;
    t.tv_usec = 0;
  }
  if(info != NULL) {
    switch(info->si_code) {
    case SI_USER:
      reason = "sent kill(2) by user";
      u = info->si_uid;
      sp = info->si_pid;
      break;
    case SI_QUEUE:
      reason = "received signal via sigqueue(3)";
      u = info->si_uid;
      sp = info->si_pid;
      break;
#ifdef SI_KERNEL
    case SI_KERNEL:
      reason = "signal sent by kernel";
      break;
#endif
    case SI_TIMER:
      reason = "POSIX timer expired";
      /* N.B. on some linuxes, the si_overrun and si_timerid fields of
       * siginfo_t give the timer_overrun(2) and the kernel ID of the timer
       * respectively -- but these are not likely to help much in diagnostics
       */
      break;
#ifdef SI_TKILL
    case SI_TKILL:
      reason = "tkill(2) or tgkill(2)";
      break;
#endif
    case SI_MESGQ:
      reason = "POSIX message queue state changed (see mq_notify(3))";
      u = info->si_uid;
      sp = info->si_pid;
      break;
    case SI_ASYNCIO:
      reason = "asynchronous I/O completed";
      break;
    }
  }
  
  msg = strsignal(signo);
  
  /* change the default signal string and/or get extra information about
   * the reason for the signal if there's more info we can glean
   */
  switch(signo) {
 
  case SIGCHLD:
    if(info != NULL) {
      u = info->si_uid;
      sp = info->si_pid;
      status = info->si_status;
#ifndef __APPLE__
      ut = info->si_utime;
      st = info->si_stime;
#endif
      switch(info->si_code) {
      case CLD_EXITED:
	msg = "child exited";
	break;
      case CLD_KILLED:
	msg = "child killed";
	break;
      case CLD_DUMPED:
	msg = "child core dumped";
	break;
      case CLD_STOPPED:
	msg = "child stopped";
	break;
      case CLD_CONTINUED:
	msg = "child continued";
	break;
       default:
	msg = "child status chanaged";
      }
    }
    break;
  case SIGILL:
    if(info != NULL) {
      switch(info->si_code) {
      case ILL_ILLOPC:
	reason = "illegal opcode";
	break;
      case ILL_ILLOPN:
	reason = "illegal operand";
	break;
      case ILL_ILLADR:
	reason = "illegal addressing mode";
	break;
      case ILL_ILLTRP:
	reason = "illegal trap";
	break;
      case ILL_PRVOPC:
	reason = "privileged opcode";
	break;
      case ILL_PRVREG:
	reason = "privileged register";
	break;
      case ILL_COPROC:
	reason = "coprocessor error";
	break;
      case ILL_BADSTK:
	reason = "internal stack error";
	break;
      }
    }
    break;
  case SIGFPE:
    if(info != NULL) {
      switch(info->si_code) {
      case FPE_INTDIV:
	reason = "integer divide by zero";
	break;
      case FPE_INTOVF:
	reason = "integer overflow";
	break;
      case FPE_FLTDIV:
	reason = "floating-point divide by zero";
	break;
      case FPE_FLTOVF:
	reason = "floating-point overflow";
	break;
      case FPE_FLTUND:
	reason = "floating-point underflow";
	break;
      case FPE_FLTRES:
	reason = "floating-point inexact result";
	break;
      case FPE_FLTINV:
	reason = "floating-point invalid operation";
	break;
      case FPE_FLTSUB:
	reason = "subscript out of range";
	break;
      }
    }
    break;
  case SIGSEGV:
    if(info != NULL) {
      switch(info->si_code) {
      case SEGV_MAPERR:
	reason = "address not mapped to object";
	break;
      case SEGV_ACCERR:
	reason = "invalid permissions for mapped object";
	break;
      }
    }
    break;
  case SIGBUS:
    if(info != NULL) {
      switch(info->si_code) {
      case BUS_ADRALN:
	reason = "invalid address alignment";
	break;
      case BUS_ADRERR:
	reason = "nonexistent physical address";
	break;
      case BUS_OBJERR:
	reason = "object-specific hardware error";
	break;
#ifdef BUS_MCEERR_AR
      case BUS_MCEERR_AR:
	reason = "hardware memory error -- action required";
	break;
#endif
#ifdef BUS_MCEERR_AO
      case BUS_MCEERR_AO:
	reason = "hardware memory error -- action optional";
	break;
#endif
      }
    }
    break;
  case SIGTRAP:
    if(info != NULL) {
      switch(info->si_code) {
      case TRAP_BRKPT:
	reason = "process breakpoint";
	break;
      case TRAP_TRACE:
	reason = "process trace trap";
	break;
#ifdef TRAP_BRANCH
      case TRAP_BRANCH:
	reason = "process taken branch trap";
	break;
#endif
#ifdef TRAP_HWBKPT	
      case TRAP_HWBKPT:
	reason = "hardware breakpoint/watchpoint";
	break;
#endif
      }
    }
    break;
  case SIGIO:
    if(info != NULL) {
#ifndef __APPLE__
      fd = info->si_fd;
#endif
      switch(info->si_code) {
      case POLL_IN:
	reason = "data input available";
	break;
      case POLL_OUT:
	reason = "output buffers available";
	break;
      case POLL_MSG:
	reason = "input message available";
	break;
      case POLL_ERR:
	reason = "I/O error";
	break;
      case POLL_PRI:
	reason = "high priority input available";
	break;
      case POLL_HUP:
	reason = "device disconnected";
	break;
      }
    }
    break;
  }
  new_message(signo, msg, reason, t, u, ut, st, sp, mp, pp, fd, status, whoami);
}
