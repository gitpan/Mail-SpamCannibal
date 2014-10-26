#!/usr/bin/perl
#
# sc_mailfilter.pl
#
# version 1.08, 11-20-04
#
#################################################################
# WARNING! do not modify this script, make one with a new name. #
# This script will be overwritten by subsequent installs of     #
# SpamCannibal.                                                 #
#################################################################
#
# Copyright 2003, 2004 Michael Robinton <michael@bizsystems.com>
   
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
use Mail::SpamCannibal::SiteConfig;
use Mail::SpamCannibal::ScriptSupport 0.09 qw(
	mailcheck
	list2NetAddr
	DO
);
use Mail::SpamCannibal::SMTPsend qw(
	sendmessage
);
use Mail::SpamCannibal::PidUtil qw(
	get_script_name
	make_pidfile
);
use Fcntl qw(:DEFAULT :flock);

################ CONFIGURABLE LIMITS ####################
# The READ limit sets the maximum buffer size for the	#
# read line operation. This should be large enough to	#
# accomodate the biggest expected PGP armored input 	#
# file + the mail headers required to deliver the	#
# message.						#
#							#
# The SAVE limit chops the text to this size before	#
# insertion into the database.				#
#########################################################


my $CHAR_READ_LIMIT = 8000;
my $CHAR_SAVE_LIMIT = 50000;

sub usage {
  print STDERR $_[0],"\n\n" if $_[0];
  print STDERR qq|
Syntax:	$0 path/to/config.file
    or
	$0 -d path/to config.file
	$0 -v path/to/config.file

The -v switch sends debug error messages to 
the REPORT target email address (if present)

The -d switch returns the information that would
be added to the tarpit and evidence databases.
Nothing is added to the database files.

|;
  exit 1;
}

# set real to effective
$< = $>;

$| = 1;
my $X = 0;
my $DEBUG = 0;
my $VERBOSE = 0;
my $config;
my $blacklist;

usage() unless @ARGV;

while ($_ = shift @ARGV) {
  if ($_ eq '-x') {
    $X = 1;
    $DEBUG = 1;  
    $VERBOSE = 2;
    next;
  }
  elsif ($_ eq '-d') {
    $DEBUG = 1;
    $VERBOSE = 1;
    next;
  }
  elsif ($_ eq '-v') {
    $VERBOSE = 1;
    next;
  } else {
    $config = $_;
  }
}

usage ('no config file') unless $config;

my $MAILFILTER = DO($config);
usage ('could not load config file')
	unless $MAILFILTER;

usage ('corrupted config file')
	unless keys %$MAILFILTER
	&& $MAILFILTER->{BLCONFIG}
	&& exists $MAILFILTER->{MXhosts}
	&& ref $MAILFILTER->{MXhosts} eq 'ARRAY'
	&& @{$MAILFILTER->{MXhosts}};

my $DNSBL = DO($MAILFILTER->{BLCONFIG});
usage ('could not load BlackList file')
	unless $DNSBL;

usage ('corrupted corrupted BlackList file')
	unless  keys %$DNSBL
	&& exists $DNSBL->{IGNORE}
	&& ref $DNSBL->{IGNORE} eq 'ARRAY'
	&& @{$DNSBL->{IGNORE}};

my $CONFIG = new Mail::SpamCannibal::SiteConfig;

# only open the db's we will need
my ($environment,$tarpit,$archive,$evidence) = (
	$CONFIG->{SPMCNBL_ENVIRONMENT},
	$CONFIG->{SPMCNBL_DB_TARPIT},
	$CONFIG->{SPMCNBL_DB_ARCHIVE},
	$CONFIG->{SPMCNBL_DB_EVIDENCE},
);

my %default = (
	dbhome  => $environment,
	dbfile  => [$tarpit],
	txtfile => [$evidence],
	DEBUG   => $DEBUG,
	LIMIT   => $CHAR_SAVE_LIMIT, # characters
	PGPLIM  => $CHAR_READ_LIMIT,
);

my $pidfile = $environment .'/'. get_script_name() .'.'. $$ .'.pid';
make_pidfile($pidfile);

# if validation is specified
push @{$default{dbhome}}, $archive
	if $MAILFILTER->{VALIDATE};

my @NAignor;
list2NetAddr($DNSBL->{IGNORE},\@NAignor)
	or usage('missing IGNORE array in BlackList file');

my $emailfmt = '^.+\@.+\..+';

my $run = 1;
local $SIG{TERM} = sub { $run = 0 };

# this is set up so that it can be enhanced to pass a file handle in a
# loop for batch message processing
#
my $fh = *STDIN;
{	# while loop
  if ( $run &&  (@_ = mailcheck($fh,$MAILFILTER,$DNSBL,\%default,\@NAignor)) &&
     ( $X ||	($MAILFILTER->{REPORT} &&
	$MAILFILTER->{REPORT} =~ /$emailfmt/))) {
    my($verb,$err) = @_;
    if ($VERBOSE || $verb > 1) {
      $err = "Subject: debug $0\n\n$err"
	unless $err =~ /Subject:/;
      if ($X) {
        print $err,"\n";
      } elsif ($run) {
        sendmessage($err,$MAILFILTER->{REPORT})
	  if $VERBOSE || $verb > 1;
      }
    }
  }
  elsif (exists $MAILFILTER->{SPAMCOUNT} &&					# spam counting active
	$MAILFILTER->{SPAMCOUNT} =~ m|.+/| &&					# extract directory portion
	-d $& &&								# directory exists
	sysopen(FILE,$MAILFILTER->{SPAMCOUNT},O_RDWR|O_CREAT) &&		# open counter file
	($_ = select(FILE)) && ($| = 1) && (select $_)) {			# flush file handle
    if (flock(FILE, LOCK_EX)) {							# block until locked
      $_ = <FILE> || 0;								# last count
      seek(FILE,0,0);								# rewind file
      print FILE $_+1,"\n";							# increment count
      truncate(FILE, tell(FILE));
    }      
    close FILE;
  }
} # end while

unlink $pidfile;
