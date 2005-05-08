#!/usr/bin/perl
#
# zone_dump.pl version 1.02, 5-7-05
#
# Copyright 2005 Michael Robinton <michael@bizsystems.com>
# rc.dnsbls is free software; you can redistribute it and/or 
# modify it under the terms of the GPL software license.
#
use strict;
use diagnostics;
use Config;
use POSIX qw(nice);
use Compress::Zlib;
use Mail::SpamCannibal::SiteConfig;
use Proc::PidUtil 0.07 qw(
        is_running
        get_script_name
        make_pidfile
        zap_pidfile
);
use Mail::SpamCannibal::ScriptSupport qw(
	DO
);


my $CONFIG = new Mail::SpamCannibal::SiteConfig;

# you can override the installation configuration variables by
# editing the configuration file 'config/dnsbls.conf' in the
# SpamCannibal home directory
#
# Set the SpamCannibal home directory if it is not
# what is found in Mail::SpamCannibal::SiteConfig
#
# $CONFIG->{SPAMCANNIBAL_HOME} = '/usr/local/spamcannibal';

# The number of times to retry the zone dump if it fails for some reason
#
my $retry = 3;			# default to try three time at most

###########################################################################
############## NO MORE CONFIGURABLE ITEMS BEYOND THIS POINT ###############
###########################################################################

nice(19) or die "nice failed\n";	# be very nice to other tasks

my $DEBUG = 0;
my $gzip = 0;
my $rbldns = 0;

while(($_ = shift @ARGV) && $_ =~ /^\-[dzr]/) {
  if ($_ eq '-d') {
    $DEBUG = $_;
  }
  elsif ($_ eq '-r') {
    $rbldns = new Mail::SpamCannibal::ScriptSupport;
  }
  elsif ($_ eq '-z') {
    $gzip = $_;
  }
# ignore invalid switches
}
my $destdir = $_;
my $timeout = shift;

die qq|
Syntax:  $0 destination_dir timeout
    or	 $0 -r destination_dir timeout
    or	 $0 -z destination_dir timeout
    or	 $0 -r -z destination_dir timeout

	-r	switch cause an rbldns
		file to be writtin as well

	-z 	switch gzips the DNS bin output
		file, expect 95% compression

	Directory to write compressed zone file and
	'records' information text file 'bl_records'

	Timeout is the maximum number of minutes
	to wait for 'dnsbls' to complete zone dump,
	recommend 5 to 15

	Currently configured for $retry retries.

	-d switch provides some process trace info

| unless $destdir && $timeout &&
	-d $destdir && -w $destdir &&
	$timeout =~ /\d/ && $timeout !~ /\D/;

$timeout *= 60;

die "USR2 signal not found in perl::Config\n"
	unless  defined $Config{sig_name} && 
		$Config{sig_name} =~ /USR2/;
my $usr2 = 0;
foreach(split(' ',$Config{sig_name})) {
  last if $_ eq 'USR2';
  ++$usr2;
}

my $DNSBLS = DO($CONFIG->{SPAMCANNIBAL_HOME} .'/config/dnsbls.conf') 
	or exit 1;

my $dbenv = $DNSBLS->{environment} || $CONFIG->{SPMCNBL_ENVIRONMENT} 
	or die "could not find SpamCannibal database environment\n";

my $zonefile = $DNSBLS->{zonename} .'.in'
	or die "zone name missing from dnsbls.conf\n";
my $zonein = $dbenv .'/'. $zonefile;
unlink $zonein if -e $zonein;		# remove old files hanging around

my $zoneout = $destdir .'/'. $zonefile;

my $dnsblpid;
my $error = '';
my @deadkids;

my $try = 'try';
RETRY:
foreach(1..$retry) {
  print STDERR "$try #$_  $error\n" if $DEBUG;
  $try = 'retry';
  $error = '';
  unless ($dnsblpid = is_running($dbenv .'/dnsbls.pid')) {
    $error = "'dnsbls' not running\n";
    sleep 120;			# give dbwatch a chance to restart stuff
    next RETRY;			# it checks every minute
  }
  kill $usr2, $dnsblpid;	# start the zone dump
  my $timer = $timeout -1;
  my $childf = '';		# child pid filename

  print STDERR "dump $zoneout to $destdir, timeout $timeout seconds\n" if $DEBUG;

  WAIT:
  foreach(1..120) {		# allow 120 seconds for task to start, then abort
    opendir(D,$dbenv) or die "failed to open database environment\n";
    @_ = grep(/dnsbls\.\d+\.pid/,readdir(D));
    closedir D;
    foreach my $kid (@_) {
      last WAIT unless grep(/$kid/,@deadkids);
    }
    $timer -= 1;
  print STDERR '.' if $DEBUG;
    sleep 1;
  }
  print STDERR "\n" if $DEBUG;
  foreach my $kid (@_) {		# there should not be more than one item alive
    next if grep(/$kid/,@deadkids);	# don't check dead kids
    print STDERR "check if $kid is alive\n" if $DEBUG;
    $childf = $dbenv .'/'. $kid;	# unless the system is not config'd right
    last if is_running($childf);
    $childf = '';
  }
  unless ($childf) {
    @deadkids = @_;
    $error = "dnsbls child not found\n";
    next RETRY;
  }
  $error = '';

  print STDERR "$childf running\ntimer = $timer  " if $DEBUG;

  while($timer > 0) {		# wait for child completion
    $timer -= 5;
    sleep 5;
    print STDERR "$timer " if $DEBUG;
    last unless is_running($childf);
  }
  print STDERR "\n" if $DEBUG;
  unless ($timer > 0) {
    $error = "timeout waiting for zone dump to complete\n";
    next RETRY;
  }
  unless (-e $zonein && -r $zonein) {
    $error = "'dnsbls' failed to create $zonein\n";
    next RETRY;
  }
  last;
}
die $error if $error;

##### have a zone file, get the record count 

open(IN,$zonein)
	or die "failed to open new zonefile\n";

my $records = '<!-- no record count found -->'."\n";

while(<IN>) {
  last unless $_ =~ /^;/;		# punt if not a header line
  if ($_ =~ /(\d+)\s+A\s+records/) {
    $records = "contains $1 A records\n";
    last;
  }
}
seek(IN,0,0);				# rewind for zip operation

if ($gzip) {
  $gzip = gzopen($zoneout .'.gz.tmp','wb')
	or die "could not open gzip zonefile\n";
}
if ($rbldns) {
  open(RBL,'>'. $zoneout .'.rbl.tmp')
	or die "could not open output rbldns file\n";
}

if ($gzip || $rbldns) {
  while(<IN>) {
    if($gzip) {
      $gzip->gzwrite($_)
	or die "error writing gzip file: $gzerrno\n";
    }
    if ($rbldns) {
      my $line = $rbldns->dns2rblz($_);
      print RBL $line if $line;
    }
  }
  if ($gzip) {
    $gzip->gzclose;
    rename $zoneout .'.gz.tmp', $zoneout .'.gz';	# atomic move
  }
  if ($rbldns) {
    print RBL "\n";
    close RBL;
    rename $zoneout .'.rbl.tmp', $zoneout .'.rbl';	# atomic move
  }
}

unless ($gzip || $destdir eq $dbenv) {
  seek(IN,0,0);			# rewind for copy operation
  open(OUT,'>'. $zoneout .'.tmp')
	or die "could not open output zonefile\n";
  while(<IN>) {
    print OUT $_;			# copy file to new destination
  }
  close OUT;
  rename $zoneout .'.tmp', $zoneout;	# atomic move
}

close IN;

unlink $zonein if ($gzip || $destdir ne $dbenv) && -e $zonein;

open(OUT,'>'. $destdir .'/bl_records.tmp')
	or die "could not open bl_records file\n";
print OUT $records;
close OUT;
rename $destdir .'/bl_records.tmp', $destdir .'/bl_records';
exit 0;
