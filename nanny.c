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

void handler(int, siginfo_t *, void *);
void new_message(int n, const char *msg, time_t t, uid_t u, pid_t sp,
		 pid_t mp, pid_t pp, int cld);
/* Data types */

typedef struct msgq {
  int signal_number;
  const char *message;
  time_t signal_time;
  uid_t signal_uid;
  pid_t signal_pid;
  pid_t my_pid;
  pid_t parent_pid;
  int child_status;
  struct msgq *tail;
} msgq_t;

/* Globals */

#define HOSTLEN 1024
#define NSIGNALS 13
#define PW_BUFSIZE 2048

pid_t pid = -1;
char hostname[HOSTLEN];
int ok = 1;
msgq_t *msg_list = NULL;
msgq_t *next_msg = NULL;
int missed_msg = 0;
const char *whoami = "nanny";

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

  pid = getpid();
  if(gethostname(hostname, (size_t)HOSTLEN) == -1) {
    snprintf(hostname, HOSTLEN, "<host unknown: %d>", errno);
  }

  memset(&action, 0, sizeof(struct sigaction));
  sigemptyset(&action.sa_mask);
  action.sa_sigaction = handler;
  action.sa_flags = SA_SIGINFO;

  for(i = 0; i < NSIGNALS; i++) {
    if(sigaction(signals[i], handler, NULL) == -1) {
      trapped[i] = 0;
    }
    else {
      trapped[i] = 1;
    }
  }


  child_pid = fork();
  if(child_pid == 0) {
    /* child */
    whoami = "child";
    pid = getpid();
    execvp(argv[0], argv);
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
    int status;
    whoami = "parent";
    do {
      switch(waitpid(child_pid, &status, WUNTRACED)) {
      case 0:
	sleep(1);
	break;
      case -1:
	perror("waitpid failed");
	exit(1);
      default:
      }
    } while(ok);
  }
}

int print_message(FILE *fp) {
  if(fp == NULL) {
    fp = stdout;
  }
  if(msg_list != NULL) {
    struct tm tim;
    int i;
    msgq_t tail;
    
    if(gmtime_r(msg_list->signal_time, &tim) != NULL) {
      fprintf(fp, "%04d%02d%02dT%02d%02d%02d ", tim.tm_year + 1900,
	      tim.tm_mon + 1, tim.tm_mday, tim.tm_hour, tim.tm_min, tim.tm_sec);
    }
    else {
      fprintf(fp, "........T...... ");
    }
    fprintf(fp, "nanny (%s %d | %d)@%s: ", whoami, (int)msg_list->my_id,
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
  }
  else {
    return 0;
  }
}

void new_message(int n, const char *msg, time_t t, uid_t u, pid_t sp,
		 pid_t mp, pid_t pp, int cld) {
  msgq_t *new_msg;

  new_msg = malloc(sizeof(msgq_t));
  if(new_msg != NULL) {
    new_msg->signal_number = n;
    new_msg->message = msg;
    new_msg->signal_time = t;
    new_msg->signal_uid = u;
    new_msg->signal_pid = sp;
    new_msg->my_id = mp;
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

void handler(int signo, siginfo_t *info, ucontext_t *context) {
  time_t t;
  uid_t u;
  uid_t sp;

  t = time(NULL);
  switch(info->si_code) {
  case SI_USER:
  case SI_QUEUE:
    u = info->si_uid;
    sp = info->si_pid;
    break;
  case SI_KERNEL:
    break;
  case SI_TIMER:
    break;
  case SI_TKILL:
    break;
  }
  switch(signo) {
  case SIGHUP:
    break;
  case SIGINT:
    break;
  case SIGQUIT:
    break;
  case SIGABRT:
    break;
  case SIGALRM:
    break;
  case SIGTERM:
    break;
  case SIGTSTP:
    break;
  case SIGCHLD:
    switch(info->si_code) {
    case CLD_EXITED:
      /* info->si_status has exit status */
    case CLD_KILLED:
    case CLD_DUMPED:
    case CLD_STOPPED:
    case CLD_CONTINUED:
    }
    break;
  case SIGXCPU:
    break;
  case SIGXFSZ:
    break;
  case SIGVTARLM:
    break;
  case SIGPROF:
    break;
  case SIGUSR1:
    break;
  case SIGUSR2:
    break;
  default:
  }
}
