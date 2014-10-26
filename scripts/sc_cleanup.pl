#!/usr/bin/perl
#
# sc_cleanup.pl
# version 1.00, 9-6-03
#
#################################################################
# WARNING! do not modify this script, make one with a new name. #
# This script will be overwritten by subsequent installs of     #
# SpamCannibal.                                                 #
#################################################################
#
# Copyright 2003, Michael Robinton <michael@bizsystems.com>
   
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
   
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
   
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#

use strict;
#use diagnostics;
use lib qw(blib/lib blib/arch);
use IPTables::IPv4::DBTarpit::Tools qw(inet_ntoa);
use Mail::SpamCannibal::SiteConfig;
use Mail::SpamCannibal::PidUtil qw(if_run_exit);
use NetAddr::IP;
use Mail::SpamCannibal::ScriptSupport qw(
	zap_one
);

sub usage {
  print STDERR $_[0],"\n\n" if $_[0];
  print STDERR qq|
Syntax:	$0 -q
    or
	$0 -d
	$0 -v

The -q switch is for normal, quiet operation.
The -d switch allows you to see what the 
script will do without any db updates 
taking place. The -v switch will print
the scripts actions to the screen. 
The -d switch implies a -v.

|;
  exit 1;
}

$| = 1;
my $DEBUG = 0;
my $VERBOSE = 0;
my $q = 0;

while ($_ = shift @ARGV) {
  if ($_ eq '-d') {
    $DEBUG = 1;
    $VERBOSE = 1;
    $q++;
    next;
  }
  elsif ($_ eq '-v') {
    $VERBOSE = 1;
    $q++;
    next;
  }
  elsif ( $_ eq '-q') {
    $q++;
  }
}

usage() unless $q;

my $CONFIG = new Mail::SpamCannibal::SiteConfig;

### EDIT these if you have an oddball configuration ###

# only open the db's we will need
my ($environment,$tarpit,$contrib,$evidence) = (
	$CONFIG->{SPMCNBL_ENVIRONMENT},
	$CONFIG->{SPMCNBL_DB_TARPIT},
	$CONFIG->{SPMCNBL_DB_CONTRIB},
	$CONFIG->{SPMCNBL_DB_EVIDENCE},
);
########## END CONFIG ##################
my %default = (
        dbhome  => $environment,
        dbfile  => [$tarpit],
        txtfile => [$contrib,$evidence],
	DEBUG	=> $DEBUG,
	VERBOSE	=> $VERBOSE,
);

if_run_exit($environment,'already running');

# strategy	IGNORE 127.xxx.xxx.xxx records
# these must be deleted by hand with sc_admin.pl
# 1)	check contents of EVIDENCE against TARPIT
# 2)	delete all EVIDENCE items from CONTRIB
# 3)	delete any EVIDENCE not in TARPIT
# 4)	check contents of CONTRIB against TARPIT
# 5)	delete any CONTRIB not found in TARPIT
# 6)	check TARPIT against CONTRIB + EVIDENCE
# 7)	delete any TARPIT not found in C or E

{
  my $config = \%default;
  my($record,$netaddy,$ip,$zapped);

  my $localnet = new NetAddr::IP('127.0.0.0','255.0.0.0');
  my $tool = new IPTables::IPv4::DBTarpit::Tools(%$config);

# 1)	check contents of EVIDENCE against TARPIT
  $record = 1;
  while($netaddy = $tool->getrecno($evidence,$record)) {
    $zapped = 0;
    $ip = inet_ntoa($netaddy);
    print "$evidence: $ip "
	if $VERBOSE;
    if (new NetAddr::IP($ip)->within($localnet)) {
	print 'skipping...' if $VERBOSE;
	next;
    }
# 2)	delete all EVIDENCE items from CONTRIB
    zap_one($tool,$netaddy,$contrib,$DEBUG,$VERBOSE,"spurious $contrib");
    next if $tool->get($tarpit,$netaddy);
# 3)	delete any EVIDENCE not in TARPIT
    $zapped = zap_one($tool,$netaddy,$evidence,$DEBUG,$VERBOSE,"not in $tarpit");
  } continue {
    $record += 1 unless $zapped;
    print "\n" if $VERBOSE;
  }
  my $tevidence = $record -1;
  print "\n$evidence = $tevidence records\n\n" if $VERBOSE;

  $record = 1;
# 4)	check contents of CONTRIB against TARPIT
  while($netaddy = $tool->getrecno($contrib,$record)) {
    $zapped = 0;
    $ip = inet_ntoa($netaddy);
    print "$contrib: ", inet_ntoa($netaddy), ' '
	if $VERBOSE;
    if (new NetAddr::IP($ip)->within($localnet)) {
	print 'skipping...' if $VERBOSE;
	next;
    }
    next if $tool->get($tarpit,$netaddy);
# 5)	delete any CONTRIB not found in TARPIT
	$zapped =  zap_one($tool,$netaddy,$contrib,$DEBUG,$VERBOSE,"not in $tarpit");
  } continue {
    $record += 1 unless $zapped;
    print "\n" if $VERBOSE;
  }
  my $tcontrib = $record -1;
  print "\n$contrib = $tcontrib records\n\n" if $VERBOSE;

  $record = 1;
# 6)	check TARPIT against CONTRIB + EVIDENCE
  while($netaddy = $tool->getrecno($tarpit,$record)) {
    $zapped = 0;
    $ip = inet_ntoa($netaddy);
    print "$tarpit: ", inet_ntoa($netaddy), ' '
	if $VERBOSE;
    if (new NetAddr::IP($ip)->within($localnet)) {
        print 'skipping...' if $VERBOSE;
        next;
    }
  next if $tool->get($contrib,$netaddy);
  next if $tool->get($evidence,$netaddy);
# 7)	delete any TARPIT not found in C or E
    $zapped = zap_one($tool,$netaddy,$tarpit,$DEBUG,$VERBOSE,"not in $contrib or $evidence");
  } continue {
    $record += 1 unless $zapped;
    print "\n" if $VERBOSE;
  }
  $record -= 1;
  if ($VERBOSE) {
    print qq|
$tarpit = $record records
$evidence = $tevidence records
$contrib = $tcontrib records
|;
  }
}
