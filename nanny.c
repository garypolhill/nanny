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

/* Globals */

#define HOSTLEN 1024;

pid_t pid = -1;
long hostid = -1L;
char hostname[HOSTLEN];

/* Main */

int main(int argc, char **argv) {
  pid_t child_pid;
  char *cmd;
  int i;
  size_t n;
  struct sigaction action;

  pid = getpid();
  if(gethostname(hostname, (size_t)HOSTLEN) == -1) {
    snprintf(hostname, HOSTLEN, "<host unknown: %d>", errno);
  }

  memset(&action, 0, sizeof(struct sigaction));
  sigemptyset(&action.sa_mask);
  action.sa_sigaction = handler;
  action.sa_flags = SA_SIGINFO;

  if(sigaction(SIGHUP, handler, NULL) == -1) {
    perror("Trapping SIGHUP");
    exit(1);
  }
  if(sigaction(SIGINT, handler, NULL) == -1) {
    perror("Trapping SIGINT");
    exit(1);
  }
  if(sigaction(SIGQUIT, handler, NULL) == -1) {
    perror("Trapping SIGQUIT");
    exit(1);
  }
  if(sigaction(SIGABRT, handler, NULL) == -1) {
    perror("Trapping SIGABRT");
    exit(1);
  }
  if(sigaction(SIGALRM, handler, NULL) == -1) {
    perror("Trapping SIGALRM");
    exit(1);
  }
  if(sigaction(SIGTERM, handler, NULL) == -1) {
    perror("Trapping SIGTERM");
    exit(1);
  }
  if(sigaction(SIGTSTP, handler, NULL) == -1) {
    perror("Trapping SIGTSTP");
    exit(1);
  }
  if(sigaction(SIGCHLD, handler, NULL) == -1) {
    perror("Trapping SIGCHLD");
    exit(1);
  }
  if(sigaction(SIGXCPU, handler, NULL) == -1) {
    perror("Trapping SIGXCPU");
    exit(1);
  }
  if(sigaction(SIGXFSZ, handler, NULL) == -1) {
    perror("Trapping SIGXFSZ");
    exit(1);
  }
  if(sigaction(SIGVTALRM, handler, NULL) == -1) {
    perror("Trapping SIGVTALRM");
    exit(1);
  }
  if(sigaction(SIGPROF, handler, NULL) == -1) {
    perror("Trapping SIGPROF");
    exit(1);
  }
  if(sigaction(SIGUSR1, handler, NULL) == -1) {
    perror("Trapping SIGUSR1");
    exit(1);
  }
  if(sigaction(SIGUSR2, handler, NULL) == -1) {
    perror("Trapping SIGUSR2");
    exit(1);
  }

  n = (size_t)0;
  for(i = 0; i < argc; i++) {
    n += strlen(argv[i]) + 1;
  }
  cmd = (char *)calloc(n + 1, sizeof(char));

  for(i = 0; i < argc; i++) {
    strcat(cmd, argv[i]);
    strcat(cmd, " ");
  }

  child_pid = fork();
  if(child_pid == 0) {
    /* child */
    hostid = gethostid();
    system(cmd);
    exit(0);
  }
  else if(child_pid == -1) {
    /* error */
    perror("fork failed");
    exit(1);
  }
  else {
    /* parent */
    
  }
}

/*      _exit(), access(), alarm(), cfgetispeed(), cfgetospeed(), cfsetispeed(), cfsetospeed(), chdir(),
     chmod(), chown(), close(), creat(), dup(), dup2(), execle(), execve(), fcntl(), fork(),
     fpathconf(), fstat(), fsync(), getegid(), geteuid(), getgid(), getgroups(), getpgrp(), getpid(),
     getppid(), getuid(), kill(), link(), lseek(), mkdir(), mkfifo(), open(), pathconf(), pause(),
     pipe(), raise(), read(), rename(), rmdir(), setgid(), setpgid(), setsid(), setuid(),
     sigaction(), sigaddset(), sigdelset(), sigemptyset(), sigfillset(), sigismember(), signal(),
     sigpending(), sigprocmask(), sigsuspend(), sleep(), stat(), sysconf(), tcdrain(), tcflow(),
     tcflush(), tcgetattr(), tcgetpgrp(), tcsendbreak(), tcsetattr(), tcsetpgrp(), time(), times(),
     umask(), uname(), unlink(), utime(), wait(), waitpid(), write(). */

void handler(int signo, siginfo_t *info, ucontext_t *context) {
  uid_t uid = -1;
  pid_t spid = -1;
  time_t sig_time;

  sig_time = time(NULL);
  switch(info->si_code) {
  case SI_USER:
  case SI_QUEUE:
    uid = info->si_uid;
    spid = info->si_pid;
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
