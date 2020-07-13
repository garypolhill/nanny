#!/usr/bin/perl
#
# tdist.pl
#
# Inspect the logs from childminder called in -f mode and gather data allowing
# plots of the distributions of how long function calls took to be inspected.
#
# Data will be gathered only from consecutive lines containing output saying
# what the answer is

use strict;

# Globals

my $LOGDIR = "log";
my @logfiles;

# Process command-line options

while($ARGV[0] =~ /^-/) {
  my $opt = shift(@ARGV);

  if($opt eq '-l' or $opt eq '--log-dir') {
    $LOGDIR = shift(@ARGV);
  }
  elsif($opt eq '-h' or $opt eq '--help') {
    print "Usage: $0 [-l <log dir>]\n";
    exit 0;
  }
  else {
    die "Option not recognized: $opt -- use -h to find out usage\n";
  }
}

# Open log directory and get relevant log files

opendir(DIR, $LOGDIR) or die "Cannot open log directory $LOGDIR: $!\n";

while(my $fn = readdir(DIR)) {
  if($fn =~ /^([a-z-]+)-(.*)-(\d+)\.txt$/) {
    my ($func, $mach, $pid) = ($1, $2, $3);

    if($func eq 'math-int' || $func eq 'math-fp' || $func eq 'string'
       || $func eq 'memory' || $func eq 'file' || $func eq 'random') {
      push(@logfiles, ["$LOGDIR/$fn", $func, $mach, $pid]);
    }
  }
}

closedir(DIR);

# Open each found log file and gather data on durations for functions

if(scalar(@logfiles) == 0) {
  die "No suitable log files found in log directory $LOGDIR\n";
}

print "function,machine,pid,usec\n";

my $prev_t = -1;

foreach my $fdata (@logfiles) {
  my ($fn, $func, $mach, $pid) = @$fdata;

  open(FP, "<", $fn) or die "Cannot read log file $fn: $!\n";

  while(my $line = <FP>) {
    $line =~ s/\s+$//;

    my $this_t;

    if($line =~ /^(\S+) \[\+([0-9.]+)\]\((.*)\): \(([a-z-]+)\) answer is/) {
      my ($datetime, $sec, $machine, $function) = ($1, $2, $3, $4);

      $this_t = $sec * 1000000;

      if($prev_t != -1) {
	print "$function,$mach,$pid,", ($this_t - $prev_t), "\n";
      }
    }
    else {
      $this_t = -1;
    }

    $prev_t = $this_t;
  }
  
  close(FP);
}

# Exit

exit 0;
