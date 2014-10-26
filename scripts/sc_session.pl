#!/usr/bin/perl -T
#
# sc_session.pl
#
# version 1.04, 8-28-03
#
#################################################################
# WARNING! if you modify this script, make a backup copy.	#
# This script will be overwritten by subsequent installs of 	#
# SpamCannibal.							#
#################################################################
#
# utility to manage web sessions securely.
# Update passwords
# insert and delete tarpit records
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
use lib qw(./ blib/lib blib/arch);
use IPTables::IPv4::DBTarpit::Tools qw(
	inet_aton
	inet_ntoa
	$DBTP_ERROR
	db_strerror
);
use Mail::SpamCannibal::ScriptSupport qw(
	DO
	unpack_contrib
);
use Mail::SpamCannibal::SiteConfig;
use Mail::SpamCannibal::Session qw(
	decode
	encode
	mac
	new_ses
	validate
	clean
);
use Sys::Hostname::FQDN qw(fqdn);
use Mail::SpamCannibal::Password qw(
	pw_gen
	pw_valid
	pw_obscure
	pw_get
);

# extract the path we're using
$0 =~ m|/scripts/sc_session|;
my $CONFIG = DO $` .'/config/sc_web.conf';
syntax('Could not open config file')
	unless $CONFIG || $ARGV[0] =~ /echo/;

my $DBCONFIG = $CONFIG->{SiteConfig} || 
	new Mail::SpamCannibal::SiteConfig;

my $secret = $CONFIG->{secret} || fqdn();

use constant S_MASK	=> 07777;
use constant S_ISVTX	=> 01000;	# sticky bit

my $session_dir	= $DBCONFIG->{SPAMCANNIBAL_HOME} .'/sess';
my $passwd_file	= $DBCONFIG->{SPAMCANNIBAL_HOME} .'/private/passwd';

my $error;

$| = 1;		# unbuffer IO

sub syntax {
  my($comment) = @_;
  $comment = '' unless $comment;
  print <<EOF;
$comment

Syntax:	sc_session.pl command [arg1] [arg2] ...

  sc_session.pl admin	on | off (command line only)
  sc_session.pl	newsess	user password 
  sc_session.pl updpass	session_id expire user newpass oldpass
  sc_session.pl	chksess session_id expire (relative)
  sc_session.pl rmvsess	session_id
  sc_session.pl insBL	session_id expire dot.quad.ip.addr stuff...
  sc_session.pl	insEVD	session_id expire dot.quad.ip.addr stuff...
  sc_session.pl delete	session_id expire dot.quad.ip.addr

  admin		returns "OK status"
	allow admin addition/deletion of users
  newsess	returns "OK session_id"
  updpass	returns OK or (error text)
	blank passwords deletes user (not self)
  chksess	returns "OK username" or (error text)
  rmvsess	returns OK or (error text)
  insBL		returns OK or (error text)
		insert blacklist contrib
		the arguments are (in order):
	addr => resp, err, remrsp, time, zone
	
	dot.quad.ip.addr =>
	127.0.0.3	# response code from our DNSBL
	"error string... from remote DNSBL or our default"
	127.0.0.x	# remote response accepted from remote DNSBL
	1059422395	# time record expires (since epoch) or "0"
	remote.dnsbl.zone
 
  insEVD	returns OK or (error text)
		insert evidence, the arguments are:
	dot.quad.ip.addr followed by STDIN of
	mail headers +
	message terminated on the last line by a single
	.

  delete	returns OK or (error text)
		deletes dot.quad.ip.addr in all databases

EOF
  exit;
}

syntax if @ARGV < 2;

my $action = shift @ARGV;

my %db_config = (	# this is the default, modified by InsXXX and Delete below
	dbfile	=> [	$DBCONFIG->{SPMCNBL_DB_TARPIT},
		],
	txtfile	=> [	$DBCONFIG->{SPMCNBL_DB_CONTRIB},
			$DBCONFIG->{SPMCNBL_DB_EVIDENCE},
		],
	dbhome	=>	$DBCONFIG->{DBTP_ENVHOME_DIR},
	umask	=>	007,
);


my $rv;
if ($action =~ /^newsess/) {	# new session
  $rv = NewSess();
}
elsif ($action =~ /^updpass/) {	# update password - possibly create new user
  $rv = UpdPass();
}
elsif ($action =~ /^chksess/) {	# check and re-validate current session
  $rv = ChkSess();
}
elsif ($action =~ /^insBL/) {	# insert a Black List item
  $rv = InsBL();
}
elsif ($action =~ /^insEVD/) {	# insert an Evidence item
  $rv = InsEVD();
}
elsif ($action =~ /^delete/) {	# delete and address from database
  $rv = Delete();
}
elsif ($action =~ /^admin/) {	# allow / disallow admin user additions/deletions
  $rv = Admin();
}
elsif ($action =~ /^sorry/) {	# command line intercept from wrapper
  $rv = 'command line execution only';
}
elsif ($action =~ /^echo/) {	# echo test
  $rv = join(' ',@ARGV);
}
elsif ($action =~ /^rmvsess/) {	# remove session
  $rv = Remove();
}
else {
  syntax;
}

print $rv,"\n";

sub getip {
  my($adr) = @_;
  $error = 'bad IP address';
  return undef unless $adr;
  my $rv = inet_aton($adr);
  return undef unless $rv;
  clean($rv);
}

sub db_open {
  $error = "Could not open $db_config{dbhome}, $DBTP_ERROR " . db_strerror($DBTP_ERROR);
  return new IPTables::IPv4::DBTarpit::Tools %db_config;
}

sub Admin {
  return 'no admin input'
	unless (my $admin = clean(shift @ARGV));
  my $me = clean($0);
  my $mode = (stat($me))[2];
  $mode &= S_MASK;
  if ('on' eq lc $admin) {
    $mode |= S_ISVTX;
  } else {
    $mode &= (S_MASK ^ S_ISVTX);
  }
  chmod $mode, $me;
  $mode = (stat($me))[2];
  $mode &= S_MASK;
  my $rv = ($mode & S_ISVTX) ? 'on' : 'off';
  return sprintf("OK admin mode %o %s",$mode,$rv);
}

sub UpdPass {
  my ($sesid,$expire,$newuser,$newpas,$oldpas) = @ARGV;
  (my $user = validate($session_dir,$sesid,$secret,\$error,$expire))
	or return $error;
  return 'missing user'
	unless $newuser;
  $newuser = clean($newuser);
  if ($oldpas) {
    $oldpas = clean($oldpas);
  } else {
    $oldpas = '';
  }

  my $adminOK = -k $0;		# test sticky bit for admin OK

  my $rv = pw_update($passwd_file,$adminOK,$user,$newpas,$oldpas,$newuser);
  return $rv || 'OK';
}

sub pw_update {
  my($passwd_file,$adminOK,$user,$newpas,$oldpas,$newuser) = @_;
  $user = '' unless $user;
  $oldpas = '' unless $oldpas;
  $newpas = $oldpas unless $newpas;
  $newuser = $user unless $newuser;
  my $error = '';
  my $cryptpass = pw_get($user,$passwd_file,\$error);
  return $error unless defined $cryptpass;

  my $pw_entry = $newuser .':';
  if ($user eq $newuser) {
    return 'invalid password'
	unless pw_valid($oldpas,$cryptpass);
    return 'can not delete self'
	if !$newpas && !$oldpas;
  } elsif (defined pw_get($newuser,$passwd_file,\$error)) {
    if ( $adminOK &&	# admin mode enabled
	 ! $newpas &&
	 ! $oldpas ) {	# delete request
      $pw_entry = '';
    } else {
      return 'unauthorized change password attempt';
    }
  } elsif ( ! $adminOK ) {		# admin new user entries not "on"
    return 'new user entry not enabled';
  }

  if ($pw_entry) {			# not a delete
    return 'blank password not allowed'
	unless $newpas;
    (my $notok,$error) = pw_obscure($newpas,$oldpas);
    return $error if $notok;
  }

  return 'could not open password file'
	unless open(PR,$passwd_file);
  my @passwdf = (<PR>);			# slurp whole file
  close PR;

  my $altered;
  my @newpasf;
  foreach(@passwdf) {
    if ($_ =~ /^$newuser:/) {
      $altered = 1;
      next unless $pw_entry;		# next if delete
      $_ = $pw_entry . pw_gen($newpas) ."\n";
    }
    push @newpasf, $_;
  }
  if ($pw_entry && !$altered) {		# add new user if not already found
    push @newpasf, $pw_entry . pw_gen($newpas) ."\n";
    $altered = 1;
  }
  return "user $newuser not found"
	unless $altered;
  return 'could not open password file for write, try later'
	unless open(PW,'>',$passwd_file . '.new');
  foreach(@newpasf) {
    print PW $_;
  }
  close PW;
  rename $passwd_file . '.new', $passwd_file;
  return '';
}

# create a complete ticket of the form
# user(base64).MAC.file
# where mac  = mac(user(base64),file,secret);
# where file = time.pid.ticket
# and ticket = mac(user(base64),time,pid,secret)
#
sub NewSess {
  my($user,$passwd) = @ARGV;
  if ($passwd) {
    $passwd = clean($passwd);
  } else {
    $passwd = '';
  }
  return $error unless defined
	(my $cryptpass = pw_get($user,$passwd_file,\$error));
  return 'invalid password'
	unless pw_valid($passwd,$cryptpass);
# validated, create ticket
  $user = encode($user);
  my $sess_id = new_ses($session_dir,$user,$secret,\$error);
  return undef
	unless $sess_id;
  return 'OK ' . $sess_id;
}

sub ChkSess {
  my($sesid,$expire) = @ARGV;
  my $user = validate($session_dir,$sesid,$secret,\$error,$expire);
  return $error
	unless $user;
  return $error
	unless defined pw_get($user,$passwd_file,\$error);
  return 'OK '. $user;
}
  
sub RmvSess {
  my $sesid = clean($ARGV[0]);
  my $file = $session_dir .'/'. (split('.',$sesid,3))[2];
  return 'session missing'
	unless -e $file && -f $file;
  return 'could not remove session file'
	unless unlink $file;
  return 'OK';
}

sub dberreturn {
  my($tool,$db,$error) = @_;
  $tool->closedb;
  return $db .', '. db_strerror($error);
}

sub InsBL {
  my ($sesid,$expire,$addr,$orsp,$err,$trsp,$tim,$zon) = @ARGV;
  validate($session_dir,$sesid,$secret,\$error,$expire) 
	or return $error;
  (my $saddr = getip($addr)) 
	or return "input addr, $error";
  $orsp = getip($orsp) 
	or return "response code, $error";
  $err = clean($err);
  $trsp = getip($trsp) 
	or return "DNSBL code, $error";
  $tim = clean($tim) || time;
  $zon = clean($zon);
  $db_config{txtfile} = [$DBCONFIG->{SPMCNBL_DB_CONTRIB}];
  (my $tool = db_open())
	or return $error;
  $error = $tool->touch($DBCONFIG->{SPMCNBL_DB_TARPIT},$saddr);
  return dberreturn($tool, $DBCONFIG->{SPMCNBL_DB_TARPIT}, $error)
	if $error;
  $error = $tool->put($DBCONFIG->{SPMCNBL_DB_CONTRIB},
		$saddr,pack("a4 x A* x a4 x N x A*",$orsp,$err,$trsp,$tim,$zon));
  return dberreturn($tool, $DBCONFIG->{SPMCNBL_DB_CONTRIB}, $error)
	if $error;
  $tool->closedb;
  return 'OK';
}

sub InsEVD {
  my ($sesid,$expire,$addr) = @ARGV;
  validate($session_dir,$sesid,$secret,\$error,$expire) 
	or return $error;
  (my $saddr = getip($addr)) 
	or return "input addr, $error";
  my $string = '';
  while($_ = <STDIN>) {
    last if $_ =~/^\.$/;
    $string .= $_;
  }
  $db_config{txtfile} = [$DBCONFIG->{SPMCNBL_DB_EVIDENCE}];
  (my $tool = db_open())
	or return $error;
  $error = $tool->touch($DBCONFIG->{SPMCNBL_DB_TARPIT},$saddr);
  return dberreturn($tool, $DBCONFIG->{SPMCNBL_DB_TARPIT}, $error)
	if $error;
  $error = $tool->put($DBCONFIG->{SPMCNBL_DB_EVIDENCE},$saddr,$string);
  return dberreturn($tool, $DBCONFIG->{SPMCNBL_DB_EVIDENCE}, $error)
	if $error;
  $tool->closedb;
  return 'OK';
}

sub Delete {
  my ($sesid,$expire,$addr) = @ARGV;
  validate($session_dir,$sesid,$secret,\$error,$expire)
	or return $error;
  (my $saddr = getip($addr)) 
	or return "input addr, $error";
  $db_config{dbfile} = [$DBCONFIG->{SPMCNBL_DB_TARPIT},
			$DBCONFIG->{SPMCNBL_DB_ARCHIVE},];
  (my $tool = db_open())
	or return $error;
  foreach (	$DBCONFIG->{SPMCNBL_DB_TARPIT},
		$DBCONFIG->{SPMCNBL_DB_ARCHIVE},
		$DBCONFIG->{SPMCNBL_DB_CONTRIB},
		$DBCONFIG->{SPMCNBL_DB_EVIDENCE},
	) {
    $error = $tool->remove($_,$saddr);
    return dberreturn($tool, $_, $error)
	if $error;
  }
    $tool->closedb; 
  return 'OK';    
}

