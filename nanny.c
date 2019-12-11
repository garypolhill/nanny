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
#include <time.h>
#include <pwd.h>
#include <sys/stat.h>

int print_message(FILE *);
#ifdef __APPLE__
void handler(int, siginfo_t *, void *);
#else
void handler(int, siginfo_t *, ucontext_t *);
#endif
void new_message(int, const char *, const char *, time_t, uid_t, clock_t,
		 clock_t, pid_t, pid_t, pid_t, int);
/* Data types */

typedef struct msgq {
  int signal_number;
  const char *message;
  const char *reason;
  time_t signal_time;
  uid_t signal_uid;
  pid_t signal_pid;
  pid_t my_pid;
  pid_t parent_pid;
  clock_t user_time;
  clock_t system_time;
  int child_status;
  struct msgq *tail;
} msgq_t;

/* Globals */

#define HOSTLEN 1024
#define NSIGNALS 13
#define PW_BUFSIZE 2048
#define DEFAULT_LOG_DIR "log"

pid_t pid = (pid_t)-1;
pid_t ppid = (pid_t)-1;
char hostname[HOSTLEN];
int ok = 1;
msgq_t *msg_list = NULL;
msgq_t *next_msg = NULL;
int missed_msg = 0;
int caught_msg = 0;
const char *whoami = "nanny";
FILE *output = NULL;

const char *signal_strs[NSIGNALS] = {
  "SIGHUP", "SIGINT", "SIGQUIT", "SIGABRT", "SIGALRM", "SIGTERM",
  "SIGTSTP", "SIGCHLD", "SIGXCPU", "SIGXFSZ", "SIGPROF", "SIGUSR1", "SIGUSR2"
};
int trapped[NSIGNALS];
int signals[NSIGNALS] = {
  SIGHUP, SIGINT, SIGQUIT, SIGABRT, SIGALRM, SIGTERM,
  SIGTSTP, SIGCHLD, SIGXCPU, SIGXFSZ, SIGPROF, SIGUSR1, SIGUSR2
};
  
/* Main */

int main(int argc, char * const argv[]) {
  pid_t child_pid;
  struct sigaction action;
  int i;
  const char *cmd;
  char * const *cmd_argv;
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

  /* Check existence and/or create a log dir */
  
  if(stat(log_dir, &log_stat) == -1) {
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

  if(asprintf(&log_file, "%s/%s-%06d.txt", log_dir, hostname, pid) < 0) {
    output = stderr;
  }
  else {
    output = fopen(log_file, "w");
    if(output == NULL) {
      output = stderr;
    }
    free(log_file);
  }

  /* Trap as many signals as we can */

  memset(&action, 0, sizeof(struct sigaction));
  sigemptyset(&action.sa_mask);
  action.sa_sigaction = &handler;
  action.sa_flags = SA_SIGINFO;

  fprintf(output, "nanny is trapping [");

  for(i = 0; i < NSIGNALS; i++) {
    if(sigaction(signals[i], &action, NULL) == -1) {
      trapped[i] = 0;
    }
    else {
      trapped[i] = 1;
      fprintf(output, " %s", signal_strs[i]);
    }
  }

  fprintf(output, " ]\n");

  /* Fork and execute the desired command in the child */

  child_pid = fork();
  if(child_pid == 0) {
    /* child */
    whoami = "child";
    ppid = pid;
    pid = getpid();
    execvp(cmd, cmd_argv);
    perror("execvp failed");
    exit(1);
  }
  else if(child_pid == -1) {
    /* error */
    perror("fork failed");
    exit(1);
  }
  else {
    /* parent */
    int status = 1;
    whoami = "parent";
    do {
      switch(waitpid(child_pid, &status, WUNTRACED | WNOHANG)) {
      case 0:			/* Only returned if WNOHANG in third arg */
	status = 0;
	break;
      case -1:
	perror("waitpid failed");
	exit(1);
      default:
	caught_msg += print_message(output);
      }
    } while(status);
  }
}

int print_message(FILE *fp) {
  if(fp == NULL) {
    fp = stdout;
  }
  if(msg_list != NULL) {
    struct tm tim;
    int i;
    msgq_t *tail;
    
    if(gmtime_r(&(msg_list->signal_time), &tim) != NULL) {
      fprintf(fp, "%04d%02d%02dT%02d%02d%02d ", tim.tm_year + 1900,
	      tim.tm_mon + 1, tim.tm_mday, tim.tm_hour, tim.tm_min, tim.tm_sec);
    }
    else {
      fprintf(fp, "........T...... ");
    }
    fprintf(fp, "nanny (%s %d | %d)@%s: ", whoami, (int)msg_list->my_pid,
	    (int)msg_list->parent_pid, hostname);
    for(i = 0; i < NSIGNALS; i++) {
      if(signals[i] == msg_list->signal_number) {
	fprintf(fp, "%s (%d) caught ", signal_strs[i], signals[i]);
      }
    }
    if(i == NSIGNALS) {
      fprintf(fp, "unknown signal (%d) caught ", msg_list->signal_number);
    }
    if(msg_list->signal_uid > (uid_t)0) {
      struct passwd pw, *result = NULL;
      char buf[PW_BUFSIZE];	/* Lazy -- should call sysconf() */

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
      fprintf(fp, "\"%s\"", msg_list->message);
    }
    else {
      fprintf(fp, "(no message)");
    }
    if(msg_list->child_status != 0) {
      fprintf(fp, " child status %d", msg_list->child_status);
    }

    tail = msg_list->tail;
    free(msg_list);
    msg_list = tail;

    return 1;
  }
  else {
    return 0;
  }
}

void new_message(int n, const char *msg, const char *reason, time_t t, uid_t u,
		 clock_t ut, clock_t st, pid_t sp, pid_t mp, pid_t pp, int cld)
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

#ifdef __APPLE__
void handler(int signo, siginfo_t *info, void *context) {
#else
void handler(int signo, siginfo_t *info, ucontext_t *context) {
#endif
  time_t t = (time_t)0;
  uid_t u = (uid_t)0;
  pid_t sp = (pid_t)-1;
  const char *msg = NULL;
  const char *reason = NULL;
  int n = signo;
  pid_t mp = pid;
  pid_t pp = ppid;
  clock_t ut = (clock_t)-1;
  clock_t st = (clock_t)-1;
  int status = 0;

  t = time(NULL);
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
    reason = "signal sent by kernal";
    break;
#endif
  case SI_TIMER:
    reason = "POSIX timer expired";
    break;
#ifdef SI_TKILL
  case SI_TKILL:
    reason = "tkill(2) or tgkill(2)";
    break;
#endif
  case SI_MESGQ:
    reason = "POSIX message queue state changed (see mq_notify(3))";
    break;
  case SI_ASYNCIO:
    reason = "asynchronous I/O completed";
    break;
  default:
    reason = NULL;
  }
  switch(signo) {
  case SIGHUP:
    msg = "hangup detected on controlling terminal or death of controlling "
      "process";
    break;
  case SIGINT:
    msg = "interrupt from keyboard";
    break;
  case SIGQUIT:
    msg = "quit from keyboard";
    break;
  case SIGILL:
    msg = "illegal instruction";
    break;
  case SIGABRT:
    msg = "abort(3) signal received";
    break;
  case SIGALRM:
    msg = "timer signal from alarm(3)";
    break;
  case SIGTERM:
    msg = "termination signal";
    break;
  case SIGTSTP:
    msg = "stop typed at terminal";
    break;
  case SIGCHLD:
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
    break;
  case SIGXCPU:
    msg = "CPU time limit exceeded -- set setrlimit(2)";
    break;
  case SIGXFSZ:
    msg = "file size limit exceeded -- set setrlimit(2)";
    break;
  case SIGVTALRM:
    msg = "virtual time alarm -- see setitimer(2)";
    break;
  case SIGPROF:
    msg = "profiling timer alarm -- see setitimer(2)";
    break;
  case SIGUSR1:
    msg = "user-defined signal 1";
    break;
  case SIGUSR2:
    msg = "user-defined signal 2";
    break;
  default:
    msg = "other signal caught";
  }
}
