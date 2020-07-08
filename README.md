# nanny (repo)

This repository contains tools for running background (batch) processes on linux machines, watching over them and trying to find out as much as possible about them if they did not terminate successfully. The current main tool is `childminder`, with `nanny` having been dropped because of its reliance on `ptrace(2)` (which seems to have fallen victim to a trend to increasingly lock down permissions on linux) and (when I did have `sudo` rights) me not understanding the documentation well enough to get the code to work properly. (It seemed to stop the child on attach and then not let it start again even when I (thought I had) told it to continue.)

## childminder (program)

Childminder uses a combination of `sigaction(2)` and `waitpid(2)` to fork a child process and then check how it progresses. There is functionality to restart the requested command if the child seems to be in trouble, but this isn't properly tested yet. (Specifically, a stopped child could cause the parent to hang.) It can also be told to run some pointless built-in functions instead of forking, which may be used to get a clearer picture of any signals that might be trying to interrupt a batch process.

### Simple usage

For the sake of a trivial example, suppose you want to run `ls -lR` as a batch job for some reason. Then to watch over it, just do:

```bash
childminder ls -lR
```

Childminder will then do the following:

+ Create a `log` directory in the current working directory if it isn't already there.
+ Create a log file for this process in the `log` directory.
+ Create a child process to run `ls -lR`.
+ In the parent process:
  + Trap as many signals as permitted.
  + Wait for the child to finish, recording in the log file anything that happens that might prevent normal termination of the child.

### Optional functionality

There are various things you might want to do to modify the basic functionality described above:

+ Input, output and error stream redirection and working directory (`-i`, `-o`, `-e` and `-w` command-line options)
+ Manage logging (`-d` and `-l` options)
+ Study the signals that might be influencing the child, but we can't pick them up because we are not using `ptrace(2)` (`-f` option)
+ Try to make sure the child finishes if it fails (`-c`, `-p`, `-r`, `-s` and `-t` options) -- **be warned**, _these options might get you in trouble_.

These are described in turn in the following subsections. The `-h` option can be used to get the following help message:

```
Usage ./childminder [-c] [-d] [-h] [-r] [-s] [-t] [-e <file>] [-f <seconds>] [-i <file>] [-l <dir>] [-o <file>] [-w <dir>] cmd ...
	-c (--continue) Attempt to continue the child if it is sent
		a stop signal
	-d (--delete) Delete log files for runs that terminated
		with exit status zero
	-e (--error) <file> Redirect child stderr to file
	-f (--function) <seconds> Run a built-in function repeatedly
		for the specified number of seconds. If this option is given,
		then cmd must be one of "math-int", "math-fp", "string",
		"file", "memory", "random" or "sleep", according to
		the operation you want to test on the machine, with random
		choosing uniformly among the foregoing options (i.e. not
		"sleep") each function call, and sleep using sleep(3) to
		wait for the specified number of seconds.
	-h (--help) Print this usage message
	-i (--input) <file> Redirect child stdin from file
	-l (--log-directory) <dir> Save log in directory dir (log by
		default). Use "stderr" or "stdout" to output log to those
		streams
	-o (--output) <file> Redirect child stdout to file
	-p (--restart-stopped) Attempt to restart the child if it is
		sent a stop signal
	-r (--restart-interrupt) Attempt to restart the child if
		waitpid(2) returns -1 with EINTR
	-s (--restart-signalled) Attempt to restart the child if it
		is terminated by a signal
	-t (--n-restart) Maximum number of times to restart the
		child (default 4)
	-w (--working-directory) <dir> Change directory to dir
		before running cmd
```

#### Redirection

By default (I understand), a child inherits the input, output and error streams of its parent. To provide specific locations to redirect these streams for the child only, you can use the `-i`, `-o` and `-e` options to redirect the input, output and error streams, respectively. Each option takes as argument the name of a file to which to redirect that stream. This will be passed to `freopen(3)` as the first argument. Output and error streams will be overwritten if they exist; input stream is opened in read-only mode.

If you use any of the options to restart the command, and childminder has wrongly understood that the original child is no longer running, there could be 'interesting' behaviour that a future version of this program will do more to avoid.

The working directory of childminder (where the log directory will be created and the child command run) can be adjusted from the current working directory using the `-w` option. (A future version should allow the working directories of the child and the parent to be adjusted separately.)

#### Logging

You can specify a different path and name for the `log` directory with the `-l` option. If the argument to `-l` is `stderr` or `stdout` no log directory or log file will be created, and all output from `childminder` will be redirected to the indicated stream. The `-d` option can be used to tell childminder to delete the log file if the child terminated with exit status 0. This allows you to limit the log files saved to those where something happened that you might want to investigate. (However, it would mean you might have doubts about whether childminder was started in the first place -- a central log file would be one place to record this, and could be the subject of a future extension.)

The following things are logged:

+ A list of signals childminder has successfully trapped after starting the child.
+ The child process having started (or restarted -- see `-p`, `-r` and `-s` options)
  + Number of restarts exhausted (see `-t` option)
+ Results from `waitpid(2)`:
  + Return `-1` from `EINTR`
  + Child stopped
    + SIGCONT sent successfully (see `-c` option)
  + Child exited
  + Child terminated by signal
  + Child dumped core (if the API provides this information)
+ Results from `getrusage(2)`
+ Parent receipt of any trapped signals (including any information provided in the `siginfo_t` argument to the handler -- see `sigaction(2)` -- including UID and PID of process that sent the signal)
+ If the built-in `sleep` option is interrupted (see `-f` option)
+ Other output from the built-in functions just to prove they did something (see `-f` option)

#### Studying the run environment

The `-f` option causes childminder to run its own built-in (nonsense) functions for a defined period of time (given in seconds as an argument to this command-line option). The `cmd` part of the childminder command line is then replaced with a choice of nonsense function to run that tests a different aspect of the system. A single call to each function takes roughly a second, though obviously performance will vary depending on your machine. The following is a list of the commands that can be given:

+ `math-int` -- perform a series of elementary operations using a `long` integer variable
+ `math-fp` -- perform a series of operations using a `double` precision floating-point variable
+ `string` -- perform a series of operations processing a `char *` (string) variable
+ `file` -- perform read/write operations on a number of files
+ `memory` -- attempt to repeatedly allocate and free various sizes of memory
+ `random` -- choose one of `math-int`, `math-fp`, `string`, `file`, or `memory` each time it is called, and run that
+ `sleep` -- an internal alternative to having `sleep(1)` and some number of seconds on the command line that notes when the `sleep(3)` call (used to implement this) was interrupted before the requested time (i.e. the argument to the `-f` command-line option).

#### Ensuring child completion

**Here be dragons**: As noted by Larry Wall, all good programmers suffer from laziness, impatience and hubris. It is the last of these that is the dragon here -- it is very tempting to believe that there's no way there can be an error with your software, and anything that caused it to fail must be some sort of systemic problem, despite the fact that your software has only been used a handful of times, and all the tools that might have caused the systemic problems are used billions of times a day around the world. Restarting processes that may have failed for a good reason is, on a shared or non-self-administered machine, questionable behaviour (i.e. _potentially_ misuse of the kind that might contravene your terms of access to the machine and/or lead to disciplinary action in professional contexts). _Before_ using these options, make very sure your code works successfully on the machine you are going to execute it as a batch job. Even this won't protect you from the case where your sysadmin has tried to kill off your processes to get on with a task they need to do or because your jobs are hogging resources. Worse: _at the time of writing this README, the restart functionality hasn't been properly tested_.

With these caveats in mind, the following functionality is available:

+ `-c` will attempt to send a `SIGCONT` to the child if the result of the `waitpid(2)` system call suggests it has been stopped. My limited testing of this option indicate this doesn't work -- the log recorded that the `SIGCONT` had been successfully delivered, but the child process behaved as though it was still stopped.
+ `-p` will attempt to restart the process if sending it `SIGCONT` fails (or if, at compile time, `SIGCONT` wasn't defined).
+ `-r` will attempt to restart the process if `waitpid(2)` returns -1 with `EINTR` as the `errno`. My understanding of this situation is that the parent has received `SIGCHLD` and this probably means the child has terminated.
+ `-s` will attempt to restart the process if the status result from the `waitpid(2)` call indicates that the child was terminated by a signal.
+ `-t` sets the maximum number of restarts (by default, `4`).

I haven't tested any of the `-p`, `-r`, `-s`, or `-t` options at the time of writing. If future, it may be better if these options are replaced by code that records the fact that the command failed, but then makes it easy for you to rerun a batch with just the failed commands.

### Extensions

+ (Implemented) Use `wait4(2)` instead of `waitpid(2)` so that the `struct rusage` for the child can be inspected and reported on. The potentially useful fields of that are `ru_[us]time` (user and system time `struct timeval`s), `ru_maxrss` (a `long` containing the maximum resident set size used in kilobytes), `ru_(min|maj)flt` (minor/major page fault `long`s), `ru_nswap` and `ru_nsignals` (number of swaps and number of signals -- both `long`s, but apparently and somewhat frustratingly these are unused), `ru_(in|out)block` (input/output count `long`s) and `ru_ni?vcsw` (numbers of (in)voluntary context switch `long`s). One reason for not doing this is that `wait4(2)` is not portable and/or appears to be deprecated. This has now been implemented using getrusage(2) instead.
+ Use the `WNOHANG` option on the `waitpid(2)/wait4(2)` system call, and gather data on other running processes in the system (by inspection of `/proc`), with a particular focus on (a) keeping track of all descendents of the child and (b) any files they have open. The latter would be useful for recording provenance automatically (and would be significant mission creep for this program) but potentially also for cleaning up files written by a failed child prior to restarting it (as an option). A third (more paranoid) option is looking for processes run by others in which there is a pattern of command run by the process and failure of a child of childminder. One reason for not implementing this is inconsistent use of `procfs` by different flavours of linux. Another is the computational cost of the overhead.
+ Add a central log file of all calls to `childminder` recording (in CSV format) commands run, which machine, and any results (especially exit status or interrupts, but the `struct rusage` data could also go in here). This could be useful for identifying patterns in resource usage and/or batch job failure. The main reason I didn't implement this already was issues with handling file locking when writing to this file.
