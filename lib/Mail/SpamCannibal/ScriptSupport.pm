#!/usr/bin/perl
package Mail::SpamCannibal::ScriptSupport;

use strict;
#use diagnostics;
BEGIN {
  use vars qw($VERSION @ISA @EXPORT_OK $ID $_scode $_tcode $_ccode $rblkbegin $rblkend);
  use IO::Socket::INET;

  $_scode = inet_aton('127.0.0.0');
  $_tcode = inet_aton('127.0.0.2');
  $_ccode = inet_aton('127.0.0.3');
}

$VERSION = do { my @r = (q$Revision: 0.14 $ =~ /\d+/g); sprintf "%d."."%02d" x $#r, @r };

use AutoLoader 'AUTOLOAD';

use Config;
use IPTables::IPv4::DBTarpit::Tools;

use NetAddr::IP;
use Net::DNS::Codes qw(
	T_ANY
	T_A
	T_TXT
	T_MX
	T_NS
	T_SOA
	T_PTR
	C_IN
	NS_PACKETSZ
	QUERY
	NOERROR
	BITS_QUERY
	RD
);
use Net::DNS::ToolKit qw(
	put16
	get16
	gethead
	newhead
	get_ns
	ttlAlpha2Num
);
use Net::DNS::ToolKit::RR;
	
use Mail::SpamCannibal::ParseMessage qw(
	limitread
	dispose_of
	skiphead
	headers
	rfheaders
	get_MTAs
	firstremote
	array2string
	string2array
);
use Mail::SpamCannibal::GoodPrivacy qw(
	decrypt
	is_pgp
);
use Mail::SpamCannibal::BDBclient qw(
	dataquery
);

use Mail::SpamCannibal::PidUtil qw(
	is_running
);

use constant SerialEntry => $_scode;
use constant TarpitEntry => $_tcode;
use constant DNSBL_Entry => $_ccode;

require Exporter;
@ISA = qw(Exporter);

use Net::DNSBL::Utilities qw(
	list2NetAddr
	matchNetAddr
	list2hash
	DO
	write_stats
	statinit
	cntinit
	A1274
	A1275
	A1276
	list_countries
);
*list2NetAddr = \&Net::DNSBL::Utilities::list2NetAddr;
*matchNetAddr = \&Net::DNSBL::Utilities::matchNetAddr;
*DO = \&Net::DNSBL::Utilities::DO;

@EXPORT_OK = qw(
	DO
	SerialEntry
	TarpitEntry
	DNSBL_Entry
	id
	question
	revIP   
	query   
	dns_ans 
	dns_ns
	zone_def
	valid127
	validIP
	zap_one
	zap_pair
	job_died
	dbjob_chk
	dbjob_kill
	dbjob_recover
	unpack_contrib
	lookupIP
	list2NetAddr
	matchNetAddr
	BLcheck
	BLpreen
	mailcheck
);

$ID = time % 65536;		# unique for now

# autoload declarations

sub DESTROY {};

=head1 NAME

Mail::SpamCannibal::ScriptSupport - A collection of script helpers

=head1 SYNOPSIS

  use Mail::SpamCannibal::ScriptSupport qw(
	DO
	SerialEntry
	TarpitEntry
	DNSBL_Entry
	id
	question
	revIP
	query
	dns_ans
	dns_ns
	zone_def
	valid127
	validIP
	zap_one
	zap_pair
	job_died
	dbjob_chk
	dbjob_kill
	dbjob_recover
	unpack_contrib
	lookupIP
	list2NetAddr
	matchNetAddr
	BLcheck
	BLpreen
	mailcheck
  );

  $rv = DO($file);
  $packedIPaddr = SerialEntry()
  $packedIPaddr = TarpitEntry();
  $packedIPaddr = DNSBL_Entry();
  $unique = id($seed);
  $querybuf = question($name,$type);
  $rev = revIP($ip);
  $response = query(\$buffer,$timeout);
  ($aptr,$tptr,$auth_zone) = dns_ans(\$buffer);
  $nsptr = dns_ns(\$buffer);
  ($expire,$error,$dnresp,$timeout)=zone_def($zone,\%dnsbl);
  $dotquad = valid127($dotquad);
  $dotquad = validIP($dotquad);
  $rv = job_died(\%jobstatus,$directory);
  $rv = dbjob_chk(\%default_config);
  dbjob_kill(\%default_config,$graceperiod);
  dbjob_recover(\%default_config);
  ($respip,$err,$blrsp,$exp,$zon)=unpack_contrib($record);
  ($which,$text)=lookupIP(\%config,$dotquadIP,$sockpath,$is_network);
  $rv=list2NetAddr(\@inlist,\@NAobject);
  $rv = matchNetAddr($ip,\@NAobject);
  $rv = BLcheck(\%DNSBL,\%default);
  $rv = BLpreen(\%DNSBL,\%default);
  @err=mailcheck($fh,\%MAILFILTER,\%DNSBL,\%default,\@NAignor)
  $rv=zap_one($tool,$netaddr,$db,$verbose,$comment);
  zap_pair($tool,$netaddr,$pri,$sec,$debug,$verbose,$comment);

=head1 DESCRIPTION

B<Mail::SpamCannibal::ScriptSupport> provides a collection of support utilities 
for sc_BLcheck, sc_BLpreen, sc_mailfilter, sc_admin, sc_session, and
cannibal.cgi.

=over 4

=item * $rv = DO($file);

Imported from Net::DNSBL::Utilities for legacy applications.

This is a fancy 'do file'. It first checks that the file exists and is
readable, then does a 'do file' to pull the variables and subroutines into
the current name space.

  input:	file/path/name
  returns:	last value in file
	    or	undef on error
	    prints warning

=item * $packedIPaddr = SerialEntry();

Returns the packed internet address equivalent to inet_aton('127.0.0.0').
Make sure and use the parens at the end of the function.

=item * $packedIPaddr = TarpitEntry();

Returns the packed internet address equivalent to inet_aton('127.0.0.2').
Make sure and use the parens at the end of the function.

=item * $packedIPaddr = DNSBL_Entry();

Returns the packed internet address equivalent to inet_aton('127.0.0.3').
Make sure and use the parens at the end of the function.

=cut

1;
__END__

############################################
############################################

=item * $unique = id($seed);

Return a unique, non-zero, 16 bit ID for this session. Seeded with time, this number is
autoincremented each time it is retrieved and will be unique each call from
a single session. The number wraps around at 65535.

  input:	[optional] seed
  returns:	the last 16 bit number +1

Optionally, the user may supply a seed for the first call. Subsquent calls
will return the previous number + 1 (mod 65536). The seed is set when the module is
instantiated if no seed is supplied.

=cut

sub id {
  my $seed = shift;
  $ID = ($seed % 65536) if $seed;
  $ID = 1 if ++$ID > 65535;
  return $ID;
}

=item * $querybuf = question($name,$type);

Create a C_IN DNS query of $type about $name.

  input:	host or domain name,
		query type
  returns:	query buffer

Supports types T_A, T_TXT, T_ANY, T_MX, T_NS, T_PTR  

=cut

sub question {
  my ($name,$type) = @_;
  return undef unless
	$type == T_NS ||
	$type == T_MX ||
	$type == T_ANY ||
	$type == T_TXT ||
	$type == T_PTR ||
	$type == T_A;

  my $buffer;
  my $offset = newhead(\$buffer,
	&id(),
	BITS_QUERY | RD,		# query, recursion desired
	1,0,0,0,			# one question
  );
  my ($get,$put,$parse) = new Net::DNS::ToolKit::RR;
  $offset = $put->Question(\$buffer,$offset,$name,$type,C_IN);
  return $buffer;
}

=item * $rev = revIP($ip);

Reverse an IP address. i.e

  78.56.34.12 = revIP(12.34.56.78);

  input:	a dot quad IP address
  returns:	reversed dot quad address

NOTE: this is an operation on ASCII characters, not packed network
addresses.

=cut

sub revIP {
  my @ip = split(/\./, shift);
  @_ = reverse @ip;
  return join('.',@_);
}
  
=item * $response = query(\$buffer,$timeout);

Sends a DNS query contained in $buffer. Return a DNS
response buffer or undef on error. If the error is catastophic (like a
timeout), $@ will be set.

  input:	pointer to query buffer,
		optional timeout (secs, def 30)
  returns:	DNS answer or undef

=cut

sub query {
  my($bp,$timeout) = @_;
  $timeout = 30 unless $timeout && $timeout > 0;;
  my @servers = get_ns();
  my $port = 53;
  my ($msglen,$response);
  my $len = length($$bp);
  foreach my $server (@servers) {
    $server = inet_ntoa($server);
    eval {
      local $SIG{ALRM} = sub {die "connection timed out, no servers could be reached"};
      alarm $timeout;
##### open socket
      my $socket = IO::Socket::INET->new(
	PeerAddr	=> $server,
	PeerPort	=> $port,
	Proto		=> 'udp',
	Type		=> SOCK_DGRAM,
      ) or die "connection timed out, no servers could be reached";

##### send UDP query
      syswrite $socket, $$bp, length($$bp);
##### read UDP answer
      unless ($msglen = sysread($socket,$response,NS_PACKETSZ)) {	# get response, size limited
	close $socket;

	my $socket = IO::Socket::INET->new(
	  PeerAddr	=> $server,
	  PeerPort	=> $port,
	  Proto		=> 'tcp',
	  Type		=> SOCK_STREAM,
	) or die "connection timed out, no servers could be reached";

##### send TCP query
	put16(\$msglen,0,$len);
	syswrite $socket, $msglen, 2;
	syswrite $socket, $$bp, $len;

##### read TCP answer
	sysread $socket, $response, 2;

	$msglen = get16(\$response,0);
	$msglen = sysread $socket, $response, $msglen;
	close $socket;
      } # using TCP
      alarm 0;
    }; # end eval
    next if $@;
    next unless $msglen;
    return $response;
  } # end if foreach, no server found
  return undef;
}

=item * ($aptr,$tptr,$auth_zone)=dns_ans(\$buffer);

Parse a DNS answer and return pointer to an array of B<A> response records
and B<TXT> records blessed into the callers namespace.

  input:	DNS answer
  returns:	pointers to two arrays,
		auth_zone name or ''

Returns an empty array unless there is at least ONE B<A> record found.

The first array contains packed IPv4 addresses of the form
returned by inet_aton (text). The second array contains text strings.

auth_zone will contain the zone name if an SOA record is found, otherwise
it will contain ''.

=cut

sub dns_ans {
  my $bp = shift;
  my $aptr = [];
  my $tptr = [];
  my $zone = '';
  my ($caller) = caller;
  my ($off,$id,$qr,$opcode,$aa,$tc,$rd,$ra,$mbz,$ad,$cd,$rcode,
	$qdcount,$ancount,$nscount,$arcount)
	= gethead($bp);

  DECODE:
  while(1) {
    last if
	$tc ||
	$opcode != QUERY ||
	$rcode != NOERROR ||
	$qdcount != 1 ||
	$ancount < 1;

    my ($get,$put,$parse) = new Net::DNS::ToolKit::RR;
    my ($off,$name,$type,$class) = $get->Question($bp,$off);
    last unless $class == C_IN;

    foreach(0..$ancount -1) {
      ($off,$name,$type,$class,my($ttl,$rdlength,@rdata)) =
	$get->next($bp,$off);
      if ($type == T_A) {
	push @$aptr, @rdata;
      } elsif ($type == T_TXT) {
	if (@rdata > 1) {
	  push @$tptr, join(' ',@rdata);
	} else {
	  push @$tptr, @rdata;
	}
      }
    }
    last if $ancount && @$aptr;	# end, if there is an answer
    last unless $arcount;	# end if there is no authority
    foreach(0..$nscount -1) {
      ($off,@_) = $get->next($bp,$off);	# toss these
    }
    foreach(0..$arcount -1) {
      ($off,$name,$type,@_) =
	$get->next($bp,$off);
      if($type == T_SOA) {
	$zone = $name;
	last DECODE;
      }
    }
    last;
  }
  return () unless @$aptr;
  bless $aptr, $caller;
  bless $tptr, $caller;
  return($aptr,$tptr,$zone);
}

=item * $nsptr = dns_ns(\$buffer);

Parse a DNS NS request answer and return pointer to a hash of name servers
and TTL's.

  $ptr->{hostname}--->{addr} = netaddr
		   |
		   *->{ttl}  = seconds

If no records are found, undef is returned

  input:	pointer to response buffer
  returns:	pointer to hash or undef

=cut

sub dns_ns {
  my $bp = shift;
  my $nsptr = {};
  my @ns;
  my ($caller) = caller;
  my ($off,$id,$qr,$opcode,$aa,$tc,$rd,$ra,$mbz,$ad,$cd,$rcode,
	$qdcount,$ancount,$nscount,$arcount)
	= gethead($bp);

  DECODE:
  while(1) {
    last if
	$tc ||
	$opcode != QUERY ||
	$rcode != NOERROR ||
	$qdcount != 1 ||
	$ancount < 1 ||
	$arcount < 1;

    my ($get,$put,$parse) = new Net::DNS::ToolKit::RR;
    my ($off,$name,$type,$class) = $get->Question($bp,$off);
    last unless $class == C_IN;

    foreach(0..$ancount -1) {
      ($off,$name,$type,$class,my($ttl,$rdlength,@rdata)) =
	$get->next($bp,$off);
      if ($type == T_NS) {
	push @ns, @rdata;
      }
    }
    last unless @ns;		# end if there is no answer
    foreach(0..$nscount -1) {
      ($off,@_) = $get->next($bp,$off); # toss these
    }
    foreach(0..$arcount -1) {
      ($off,$name,$type,$class,my($ttl,$rdlength,@rdata)) =
	$get->next($bp,$off);
      if ($type == T_A && grep($name eq $_,@ns)) {
	$nsptr->{"$name"}->{addr} = $rdata[0];	# return first available ns address
	$nsptr->{"$name"}->{ttl} = $ttl;
      }
    }
    last;
  }
  return undef unless keys %$nsptr;
  bless $nsptr, $caller;
  return $nsptr;
}

=item * ($expire,$error,$dnresp,$timeout)=zone_def($zone,\%dnsbl);

Parse the zone information and return either the default values or the
overides from the config file.

  Defaults:
	$expire	= '7d' 	# in seconds
	$error	= 'Blacklisted by: $zone'
	$dnresp	= inet_aton('127.0.0.3')
	$timeout  undef

NOTE: if the respone code found in the config file is not in the 127./8
block or is less than 127.0.0.3, $dnresp will be set to the default value.

=cut

sub zone_def {
  my ($zone,$zp) = @_;
  my $expire = $zp->{"$zone"}->{expire} || '7d';
  $expire = ttlAlpha2Num($expire);

  my $error = $zp->{"$zone"}->{error} || 'Blacklisted by: '.$zone;

  my $dnresp = inet_aton(valid127($zp->{"$zone"}->{response}));

  my $timeout = $zp->{"$zone"}->{timeout};

  return($expire,$error,$dnresp,$timeout);
}

=item * $dotquad = valid127($dotquad);

This function checks an IP address in dot quad notation to see if it is in
the range 127.0.0.3 to 127.255.255.255. It returns 127.0.0.3 if the IP
address is outside that range.

  input:	dot quad ip address
  returns:	input or 127.0.0.3

=cut

sub valid127 {
  my ($IP) = @_;
  return '127.0.0.3' unless $IP;
  $IP =~ s/\s//g;
  return '127.0.0.3' unless inet_aton($IP);

  unless ($rblkbegin) {	# fill object cache if empty
    $rblkbegin	= NetAddr::IP->new('127.0.0.3')->numeric();
    $rblkend	= NetAddr::IP->new('127.255.255.255')->numeric();
  }

  my $rcode = NetAddr::IP->new($IP)->numeric();
  return '127.0.0.3' if $rcode < $rblkbegin || $rcode > $rblkend;
  return $IP;
}

=item * $dotquad = validIP($dotquad);

This function inspects an IP address and returns it if is valid.

  input:	dot quad address
  returns:	dot quad address or undef

=cut

sub validIP {
  my ($IP) = @_;
  return undef unless $IP;
  $IP =~ s/\s//g;
  return undef unless $IP =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  eval {return inet_ntoa(inet_aton($IP))};
}

=item * $rv=zap_one($tool,$netaddr,$db,$verbose,$comment);

Helper function to remove a record from one database. It conditionally
removes the record from $db. No removal is performed if $debug is
true, it is just "commented". Action or proposed action is commented if
$debug or $verbose is true.
$comment is appended to the standard "remove" message if $comment exists.

  input:	$tool,	  # ref to Tools
		$netaddr, # IP to remove
		$db,	  # database name
		$debug,	  # mode
		$verbose, # report intensity
		$comment,

  output:	1 on removal, 0 if no record removed

=cut

sub zap_one {
  my($tool,$netaddr,$db,$debug,$verbose,$comment) = @_;
  $comment = ($comment) ? ', '.$comment : '';
  if ($debug) {
    print "would remove$comment"
	if $tool->get($db,$netaddr);
  }
  else {
    $_ = $_ = $tool->remove($db,$netaddr);
    if (defined $_ && !$_) {	# if record was really removed
      $tool->sync($db);
      print "remove$comment"
	if $verbose;
      return 1;
    }
  }
  return 0;
}

=item * zap_pair($tool,$netaddr,$pri,$sec,$debug,$verbose,$comment);

Helper function for B<BLpreen>. It conditionally removes the records for
$netaddr from databases $pri and $sec. No removal is performed if $debug is
true, it is just "commented". Action or proposed action is commented if $debug or $verbose is true.
$comment is appended to the standard "remove" message if $comment exists.

  input:	$tool,	  # ref to Tools
		$netaddr, # IP to remove
		$pri,	  # database name
		$sec,	  # database name
		$debug,	  # mode
		$verbose, # report intensity
		$comment,

  output:	false on success, or
		an error message

=cut

# tack on ", comment" if DEBUG or VERBOSE and comment

sub zap_pair {
  my($tool,$key,$pri,$sec,$debug,$verbose,$comment) = @_;
  $comment = ($comment) ? ', '.$comment : '';
  if ($debug) {
    print "would remove${comment}";
    return;
  } elsif ($verbose) {
    print "remove${comment}";
  }
  unless ($tool->remove($pri,$key)) {
    $tool->sync($pri);
  }
  unless ($tool->remove($sec,$key)) {
    $tool->sync($sec);
  }
}

=item & $rv = job_died(\%jobstatus,$directory);

This function checks for pid files in the $directory. The absolute
pid file path is inserted into %jobstatus with a value of it's pid.
Tasks that are not running return a pid value of zero (0).

  input:	pointer to job status hash,
		pid file directory
  returns:	true if a task is not running
		else false

=cut

sub job_died {
  my($jsp, $dir) = @_;	# get job status pointer
  opendir(PIDS,$dir) || die "could not open DB $dir directory\n";
  my @pidfile = grep(/\.pid$/,readdir(PIDS));
  closedir PIDS;
  my $dead = 0;
  my $running;
  foreach(@pidfile) {
    unless ($running = is_running($dir .'/'. $_)) { # check for normal exit that has now removed it's pid file
      next unless -e $dir .'/'. $_;		    # ignore bogus entry
      $dead = 1;
    }
    $jsp->{$dir .'/'. $_} = $running;
  }
  return $dead;
}

=item * $rv = dbjob_chk(\%default_config);

This function checks if data base tasks have exited abnormally. If an abnormal exit
is detected, the file B<blockedBYwatcher> containing the watcher pid is created in the environment
directory and the function return false, otherwise it returns true.

  input:	pointer to db configuration,
  returns:	true if all known tasks are running
		or exited normally, else returns false

=cut

sub dbjob_chk {
  my($default) = @_;
  my %jobstatus;
  return 1 unless job_died(\%jobstatus,$default->{dbhome});

  open(BLOCKED,'>'. $default->{dbhome} .'/blockedBYwatcher');
  print BLOCKED $$,"\n";
  close BLOCKED;
  return 0;
}

=item * dbjob_kill(\%default_config,$graceperiod);

This function kills all db tasks that have registered PID files in the environment
directory. These jobs are shutdown, first with a SIG TERM and if they do not
respond withing the grace period, a SIG KILL.

  input:	pointer to db configuration,
		task shutdown grace period
  returns:	nothing

=cut

sub dbjob_kill {
  my($default,$gracep) = @_;
  $gracep = 3 unless $gracep > 2;
  my $signal = 15;			# kill signal is polite to begin with
  my %jobstatus;
  while ($gracep > 0) {
    %jobstatus = ();
    job_died(\%jobstatus,$default->{dbhome});	# get pid files of remaining jobs
    my %tmp = reverse %jobstatus;
    if ($tmp{$$}) {
      delete $jobstatus{$tmp{$$}};		# remove ME
    }
    last unless keys %jobstatus;
    foreach(keys %jobstatus) {
      next if $jobstatus{$_} == $$;	# skip me
      if ($jobstatus{$_}) {		# job running when checked
	kill $signal, $jobstatus{$_};
	no warnings;
	waitpid($jobstatus{$_},0);	# reap if the user was sloppy
      } else {
	unlink $_;		# remove pid files for dead jobs
      }
    }
    $gracep--;
    unless ($gracep > 2) {
      $signal = 9;		# on last try, kill forceably
    }
    sleep 1;
  }
}

=item * dbjob_recover(\%default_config);

This function destroys and reinstantiates the database environment. The file
B<blockedBYwatcher> is removed from the environment directory if it is
present. 

All DB tasks should be terminated prior to calling this function. 

DO NOT call this job for a DB environment that has not been initialized.

 usage: if(dbjob_chk(\%default_config) {
	  dbjob_kill(\%default_config,$graceperiod);
	  dbjob_recover(\%default_config);
	... restart db jobs
	}

  input:	pointer to db configuration,
  returns:	nothing

=cut

sub dbjob_recover {
  my($default) = @_;
# all jobs should be dead
# get the UID and GID of the environment files
  opendir(ENVF,$default->{dbhome}) || die "could not open DB $default->{dbhome} directory\n";
  my @env = grep(/^__/,readdir(ENVF));
  closedir ENVF;
  my($mode,$uid,$gid) = (stat($default->{dbhome} .'/'. $env[0]))[2,4,5];
  $mode &= 0777;
    
  my %local_default = %$default;
  $local_default{recover} = 1;
# recover the environment
  my $tool = new IPTables::IPv4::DBTarpit::Tools(%local_default);
  $tool->closedb;

# restore permissions
  opendir(ENVF,$default->{dbhome}) || die "could not open DB $default->{dbhome} directory\n";
  @env = grep(/^__/,readdir(ENVF));
  closedir ENVF;
  foreach(@env) {
    chmod $mode, $default->{dbhome} .'/'. $_;
    chown $uid, $gid, $default->{dbhome} .'/'. $_;
  }

# it's now ok to restart jobs
  unlink $default->{dbhome} .'/blockedBYwatcher';	# remove the job block
}

=item * ($respip,$err,$blrsp,$exp,$zon)=unpack_contrib($record);

Unpack a 'blcontrib' record.

  input:	record from 'blcontrib' database
  output:	netaddr - our response code,
		our error message,
		netaddr - remote response code,
		dnsbl zone

This undoes pack("a4 x A* x a4 x N x A*",@_);

=cut

sub unpack_contrib {
  my ($ip,$rest) = unpack("a4 x a*",shift);
  my ($err,$rst2) = split(/\0/,$rest,2);
# using A* here instead of a*, strips everything after 'zon'
  my ($rsp,$exp,$zon) = unpack("a4 x N x A*",$rst2);
  return ($ip,$err,$rsp,$exp,$zon);
}

=item * ($which,$text)=lookupIP(\%config,$dotquadIP,$sockpath,$is_network);

This function checks the SpamCannibal databases for the
presence of an IP address and returns a text string describing why the IP address is in the
SpamCannibal data base or a descriptive not found message.

  input: (localhost)
		\%database config,
		dotquad IP address,
		/path/to/fifo,
		0,
	 (or remote host)
		\%database config,
		dotquad IP address,
		hostname:port,
		timeout seconds 

  returns:	which database,
		text string

	which = 0 for evidence
		1 for blcontrib

NOTE: the database config hash is the same as returned by Mail::SpamCannibal::SiteConfig

Text error return messages: message, meaning

invalid IP address, says it all
not found in system database, not in tarpit db
remote data record missing, found in contrib no text
no remote data record found, says it all

=cut

sub lookupIP {
  my($CONFIG,$dotquad,$sockpath,$timeout) = @_;
  $dotquad =~ s/\s//g;
  my $IP = inet_aton($dotquad);
  return (0,'invalid IP address')
	unless $IP;

  @_ = dataquery(0,$IP,$CONFIG->{SPMCNBL_DB_TARPIT},$sockpath,$timeout);
  return (0,$@) unless @_;

  my($key,$val) = @_;
  return (0,'not in '. $CONFIG->{SPMCNBL_DB_TARPIT} .' database') 
	if !$key || $key eq INADDR_NONE;

  @_ = dataquery(0,$IP,$CONFIG->{SPMCNBL_DB_EVIDENCE},$sockpath,$timeout);
  return (0,$@) unless @_;

  ($key,$val) = @_;
  if(!$key || $key eq INADDR_NONE || ! $val) {		# if not in 'evidence'
    @_ = dataquery(0,$IP,$CONFIG->{SPMCNBL_DB_CONTRIB},$sockpath,$timeout);
    return (1,$@) unless @_;
    ($key,$val) = @_;
    if ($key && $key ne INADDR_NONE && $val) { 		# if in contrib
      my($respip,$err,$blrsp,$exp,$zon)=unpack_contrib($val);
      $val = $err || 'remote data record missing';
    }
    else {						# else not in 'contrib'
      $val = 'no data record found';
    }
    return (1,$val);
  }
  else {
    return(0,$val);
  }
}

=item * $rv=list2NetAddr(\@inlist,\@NAobject);

Imported from Net::DNSBL::Utilities for legacy applications

Build of NetAddr object structure from a list of IPv4 addresses or address
ranges. This object is passed to B<matchNetAddr> to check if a given IP
address is contained in the list.

  input:	array reference pointer
		to a list of addresses

  i.e.		11.22.33.44
		11.22.33.0/24
		11.22.33.0/255.255.255.0
		11.22.33.20-11.22.33.46
		11.22.33.20 - 11.22.33.46

  output:	Number of objects created
		or undef on error

The NAobject array is filled with NetAddr::IP object references.

=item * $rv = matchNetAddr($ip,\@NAobject);

Imported from Net::DNSBL::Utilities for legacy applications

Check if an IP address appears in a list of NetAddr objects.

  input:	dot quad IP address,
		reference to NetAddr objects
  output:	true if match else false

=item * $rv = BLcheck(\%DNSBL,\%default);

This function checks the each IP address found in the 'archive' database
{SPMCNBL_DB_ARCHIVE} against the list of DNSBL's found in the
"sc_addspam.conf" configuration file. IP addresses which match the
acceptance criteria are added to the 'tarpit' database {SPMCNBL_DB_TARPIT}
and a corresponding entry is made in the 'blcontrib' database {SPMCNBL_DB_CONTRIB}
giving the reason for the addition.

  input:	config file hash ref,
		db config hash ref
  output:	false on success, or
		an error message

See: config/sc_BlackList.conf.sample for a detailed description of each
element in the configuration file. See: scripts/sc_BLcheck.pl for usage and
configuration information for the db config hash reference.

This routine will return if it catches a SIGTERM. The longest it will wait
is the timeout for a DNS query.

=cut

sub BLcheck {
  my($DNSBL,$default) = @_;
  my %count;
# extract vars
  my $DEBUG	= $default->{DEBUG} || 0;
  my $VERBOSE	= $default->{VERBOSE} || 0;
  my $tarpit	= $default->{dbfile}->[0];
  my $archive	= $default->{dbfile}->[1];
  my $contrib	= $default->{txtfile}->[0];

  my @NAignor;
  list2NetAddr($DNSBL->{IGNORE},\@NAignor)
	or return('missing IGNORE array in config file');

  my @NAblock;
  list2NetAddr($DNSBL->{BLOCK},\@NAblock);

  my $run = 1;
  local $SIG{TERM} = sub { $run = 0 };	# graceful exit;
	
  (my $tool = new IPTables::IPv4::DBTarpit::Tools(%$default))
	or return('could not open database environment, check your installation');

  my $numberoftries = 6;

  cntinit($DNSBL,\%count);
  my %deadDNSBL;
  foreach(keys %count) {
    $deadDNSBL{$_} = $count{$_};
  }
  list2hash($DNSBL->{BBC},\%count);

  my($BBC,$cc2name) = _bbc($DNSBL);

# set up statistics file for DNSBL's if configured
  my $statinit = statinit($DNSBL->{STATS},\%count);
  my $stats = '';
  $stats = $DNSBL->{STATS} if $statinit;

  my $cursor = 1;		# carefull!! bdb starts with a cursor of 1, not zero
  my $key;
  Record:
  while ($run && ($key = $tool->getrecno($archive,$cursor))) {
# get each entry in the archive
    my $IP = inet_ntoa($key);
    print "Checking $IP " if $VERBOSE;
    if (matchNetAddr($IP,\@NAignor)) {		# skip if ignored
      print "ignored " if $VERBOSE;
      next Record;
    }
    if ($tool->get($tarpit,$key)) {		# skip if it's already in tarpit
      print "in $tarpit " if $VERBOSE;
      next Record;
    }
    my $dnsblIP = revIP($IP);			# get the reversed IP address

    if (matchNetAddr($IP,\@NAblock)) {		# block if listed in reject list
      print 'BLOCK net-range ' if $VERBOSE;
      my $reason = 'blocked';
      my $error = $DNSBL->{REJECT} || 'in my bad address list';
      my $expire = 2592000;			# 30 day expiration
      my $zone = 'BLOCK';
      my $ipA = '127.0.0.5';
      my $netA = A1275;
      my $dnresp = $netA;
      _addTPentry($tool,$reason,$error,$IP,$expire,\%count,$zone,$ipA,$dnresp,$tarpit,$netA,$key,$contrib,$DEBUG,$VERBOSE);
      next Record;
    }      

    my $cc;
    if ($BBC && 
	($cc = $BBC->country_code_by_addr($IP)) &&
	grep($cc eq $_,@{$DNSBL->{BBC}})
	) { # block if Country not allowed
      my $reason = "$cc ($cc2name->{$cc}) rejected";
      print "blocked - $reason " if $VERBOSE;
      my $error = $DNSBL->{REJECT} || 'in my bad country list';
      my $expire = 2592000;			# 30 day expiration
      my $zone = $cc;
      my $ipA = '127.0.0.6';
      my $netA = A1276;
      my $dnresp = $netA;
      _addTPentry($tool,$reason,$error,$IP,$expire,\%count,$zone,$ipA,$dnresp,$tarpit,$netA,$key,$contrib,$DEBUG,$VERBOSE);
      next Record;
    }

# check in each available DNSBL until exhausted or entry is found
   CheckZone:
    foreach my $zone (sort {$count{"$b"} <=> $count{"$a"}} keys %deadDNSBL) {
      last Record unless $run;			# SIGTERM ?
      next CheckZone if $deadDNSBL{"$zone"} > $numberoftries;
      my ($expire,$error,$dnresp,$timeout) = zone_def($zone,$DNSBL);
      print $zone,' ' if $VERBOSE;

      if ($zone eq 'in-addr.arpa') {
	my $qbuf = question($dnsblIP.'.in-addr.arpa',T_PTR());
	my $response = query(\$qbuf,$timeout);
	$deadDNSBL{"$zone"} = 0;		# unconditional
	next CheckZone
		if $response && scalar get16(\$response,6);	# check for good response and any ANSWER
# block for any response failure
	$dnresp = A1274;			# unconditional
	my $reason = ($response) ? 'no reverse DNS' : 'reverse DNS timeout';
	print "blocked - $reason " if $VERBOSE;
	my $ipA = '127.0.0.4';
	my $netA = $dnresp;
	_addTPentry($tool,$reason,$error,$IP,$expire,\%count,$zone,$ipA,$dnresp,$tarpit,$netA,$key,$contrib,$DEBUG,$VERBOSE);
	next Record;
      }
      my $qbuf = question($dnsblIP.'.'.$zone,T_ANY());
      my $response = query(\$qbuf,$timeout);
      if ($response && (@_ = dns_ans(\$response))) {
	$deadDNSBL{"$zone"} = 0;		# reset retry count
      } else {
	$deadDNSBL{"$zone"} += 1 if $@;		# increment retry count
	next CheckZone;
      }
# found an entry
      my ($aptr,$tptr) = @_;
# check the A records for acceptable codes until one is found
      my $netA;
      foreach $netA (@$aptr) {
	my $ipA = inet_ntoa($netA);
	foreach(keys %{$DNSBL->{"$zone"}->{accept}}) {
	  next unless ($_ eq $ipA);
  # found one, enter it in the tarpit
  # $netA contains the accepted code
  # find or create the TXT entry
	  my $reason = $DNSBL->{"$zone"}->{accept}->{"$_"};
	CheckTxt:
	  while(1) {
	    last CheckTxt unless @$tptr;
	    if (grep($_ =~ /spam/i,@$tptr)) {
	      foreach (@$tptr) {
		next unless $_ =~ /spam/i;
		$reason = $_;
		last CheckTxt;
	      }
	    } elsif (grep($_ =~ /smtp/i,@$tptr)) {
	      foreach (@$tptr) {
		next unless $_ =~ /smtp/i;
		$reason = $_;
		last CheckTxt;
	      }
	    } else {
	      $reason = $tptr->[0];
	    }
	    last CheckTxt;
	  }
	  _addTPentry($tool,$reason,$error,$IP,$expire,\%count,$zone,$ipA,$dnresp,$tarpit,$netA,$key,$contrib,$DEBUG,$VERBOSE);
	  last CheckZone;
	}
      }
    } # CheckZone
  } continue {
    print "\n" if $VERBOSE;
    if ($DEBUG) {
      $cursor++;
    } else {
# this will force renumbering of the cursor
      unless ($tool->remove($archive,$key)) {
	$tool->sync($archive);
      }
    }
  }

  if ($VERBOSE) {
    foreach(sort {
	if ($a =~ /\./ && $b !~ /\./) {
		-1;
	}
	elsif ($a !~ /\./ && $b =~ /\./) {
		1;
	}
	else {
		$count{$b} <=> $count{$a};
	}

	} keys %count) {
      print $count{"$_"}, "\t$_\n";
    }
  }

  write_stats($stats,\%count,$statinit);
  $tool->closedb;
  return '';
}

# return pointer to Geo::IP object and pointer to array of CC => names
#
# input:	$DNSBL
# returns:	BBC, \%cc2names

sub _bbc {
  my($DNSBL) = @_;
  return () unless ($DNSBL->{BBC} && ref $DNSBL->{BBC} eq 'ARRAY' && @{$DNSBL->{BBC}});
  require Geo::IP::PurePerl;
  my $BBC = new Geo::IP::PurePerl;
  my $cp = {};
  my($countries,$code3s,$names) = list_countries;
  no warnings;
  @{$cp}{@$countries} = @$names;
  my $caller = caller;
  bless $cp, $caller;
  return ($BBC,$cp);
}

# add a tarpit entry
#
# returns:	nothing
#
# $tool		pointer to db object
# $reason	something like 'rejected, China'
# $error	something like 'in my bad country list' or 'see: http://whatsit.com?ip='
# $IP		lookup 12.34.56.78
# $expire	time in seconds, typically 30 days or less
# $cp		\%count		statistics
# $zone		BBC, BLOCK, some.rbl.com
# $ipA		response from remote DNS in text
# $dnresp	our packed netaddr response
# $tarpit	DB pointer
# $netA		response from remote DNS - netaddr [inet_aton($ipA)]
# $key		netaddr $IP - address of interest  [inet_aton($IP)]
# $contrib	DB pointer

sub _addTPentry {
  my($tool,$reason,$error,$IP,$expire,$cp,$zone,$ipA,$dnresp,$tarpit,$netA,$key,$contrib,$DEBUG,$VERBOSE) = @_;
	  if ($reason =~ m|http://.+\..+| or $reason =~ /www\..+\..+/) {
	    $error = $reason;
	  } else {
	    $error .= $IP		# append IP address if ends in http query string
		if $error =~ /\?.+=$/ || $error =~ /\?$/;
	    $error = $reason .', '. $error;
	  }

	  $expire += time;		# absolute expiration time
	  $cp->{"$zone"} += 1 if exists $cp->{"$zone"};

# create a text record of the form:
# response_code."\0".error_message."\0".dnsbl_code."\0".expire."\0".zone."\0".host

	  if ($VERBOSE > 1) {
	    $_ =  qq|
zone => $zone response => $ipA
  record |. $IP .qq| => |. inet_ntoa($dnresp) . qq| $error
  timeout |. scalar localtime($expire) .q|

|;
	    print $_;

	  }
	  elsif ($VERBOSE) {
	    if ($DEBUG) {
	      print "would add to $tarpit";
	    } else {
	      print "added to $tarpit";
	    }
	  }

	  unless ($DEBUG) {
	    $_ = pack("a4 x A* x a4 x N x A*",$dnresp,$error,$netA,$expire,$zone);
	    unless ($tool->put($contrib,$key,$_)) {
	      $tool->sync($contrib);
	      unless (	$tool->touch($tarpit,$key) ||		# add the tarpit entry
			$tool->touch($tarpit,SerialEntry())) {	# and update the serial number
		$tool->sync($tarpit);
	      }
	    }
	  }
}

=item * $rv = BLpreen(\%DNSBL,\%default);

This function validates each IP address found in the 'blcontrib' database
{SPMCNBL_DB_CONTRIB} for presence of its original dnsbl zone entry in the
configuration file and that the remote dnsbl still has an acceptable 'A'
record. IP addresses which fail either of these criteria or for which the
remote dnsbl does not respond for the 'expire' interval (see
sc_addspam.conf) are removed from the 'tarpit' database {SPMCNBL_DB_TARPIT}
as well as the 'blcontrib' database {SPMCNBL_DB_CONTRIB}. 'contrib' items 
found in the 'evidence' are unconditionally discarded instead of being checked.

  input:	config file hash ref,
		db config hash ref
  output:	false on success, or
		an error message

See: config/sc_BlackList.conf.sample for a detailed description of each
element in the configuration file. See: scripts/sc_BLpreen.pl for usage and
configuration information for the db config hash reference.

This routine will return if it catches a SIGTERM. The longest it will wait is
the timeout interval for a DNS query.

=cut

sub BLpreen {
  my($DNSBL,$default) = @_;

# extract vars
  my $DEBUG	= $default->{DEBUG} || 0;
  my $VERBOSE	= $default->{VERBOSE} || 0;
  my $tarpit	= $default->{dbfile}->[0];
  my $contrib	= $default->{txtfile}->[0];
  my $evidence	= $default->{txtfile}->[1];

  my $localnet = new NetAddr::IP('127.0.0.0','255.0.0.0');
  my @NAignor;
  list2NetAddr($DNSBL->{IGNORE},\@NAignor)
	or return('missing IGNORE array in config file');

  my @NAblock;
  list2NetAddr($DNSBL->{BLOCK},\@NAblock);

  my($BBC,$cc2name) = _bbc($DNSBL);

  my $run = 1;
  local $SIG{TERM} = sub { $run = 0 };  # graceful exit;

  (my $tool = new IPTables::IPv4::DBTarpit::Tools(%$default))
	or return('could not open database environment, check your installation');

  my $numberoftries = 6;

  my %deadDNSBL;
  foreach(keys %$DNSBL) {
    $deadDNSBL{"$_"} = ($_ =~ /.+\..+/)	# skip non-dnsbl entries
	? 1
	: $numberoftries + 1	# big... to force skip
  }

  list2hash($DNSBL->{BBC},\%deadDNSBL,1);	# set countries to count of one
  $deadDNSBL{BLOCK} = 1;
  $deadDNSBL{BBC} = 1;

  my $cursor = 1;		# carefull!! bdb starts with a cursor of 1, not zero

  my $now = time;
  my ($key,$validate,$zapped);
  Record:
  while ($run && (@_ = $tool->getrecno($contrib,$cursor))) {
    $zapped = 0;
    $validate = 0;
# get each entry in the contrib database
    my($key,$data) = @_;
    my $IP = inet_ntoa($key);
    print "$IP " if $VERBOSE;
    if (new NetAddr::IP($IP)->within($localnet)) {	# ignore 127.x.x.x addresses
      print 'skipping...' if $VERBOSE;
      next Record;
    }
    unless ($tool->get($tarpit,$key)) {		# remove if not in tarpit
      zap_pair($tool,$key,$tarpit,$contrib,$DEBUG,$VERBOSE,"not in $tarpit");
      $zapped = 1;
      next Record;
    }
    if (matchNetAddr($IP,\@NAignor)) {		# remove if in ignore database
      zap_pair($tool,$key,$tarpit,$contrib,$DEBUG,$VERBOSE,'ignore');
      $zapped = 2;
      next Record;
    }
    if ($tool->get($evidence,$key)) {		# if it's in the evidence file, zap it here
      zap_one($tool,$key,$contrib,$DEBUG,$VERBOSE,"is in $evidence");
      $zapped = 3;
      next Record;
    }
    my $dnsblIP = revIP($IP);			# get the reversed IP address
    my($orsp,$err,$trsp,$exp,$zon)=unpack_contrib($data);
    print $zon, ' ' if $VERBOSE;
    if (! ($orsp eq A1276 && $zon =~ /^[A-Z0-9]{2}$/) &&	# not a country
	! exists $DNSBL->{"$zon"}				# zone has been removed from config
	) {		

#    unless (exists $DNSBL->{"$zon"}) {			# zone has been removed from config
      zap_pair($tool,$key,$tarpit,$contrib,$DEBUG,$VERBOSE,'zone not in config');
      $zapped = 4;
      next Record
    }
    if (exists $deadDNSBL{"$zon"} && $deadDNSBL{"$zon"} > $numberoftries) {
      if ($exp < $now) {
	zap_pair($tool,$key,$tarpit,$contrib,$DEBUG,$VERBOSE,'expired (4)');
	$zapped = 5;
      }
      next Record;
    }
# get current zone info from config file
    my ($expire,$error,$dnresp,$timeout);
    if ($zon =~ /.+\..+/) {
      ($expire,$error,$dnresp,$timeout) = zone_def($zon,$DNSBL);
    }

# BLOCKED?
    if ($zon eq 'BLOCK') {			# check unconditional block
      if (matchNetAddr($IP,\@NAblock)) {
	$validate = 1;
	my $reason = 'blocked';
	my $error = $DNSBL->{REJECT} || 'in my bad address list';
	my $expire = 2592000;			# 30 day expiration
	my $ipA = '127.0.0.5';
	my $netA = A1275;
	my $dnresp = $netA;
	_updateTpentry($tool,$reason,$error,$IP,$expire,$ipA,$dnresp,$netA,$zon,$contrib,$key,$tarpit,$DEBUG,$VERBOSE);
      } else {
	$zapped = 'no longer BLOCKed';
      }
    }

# Country Code is two characters and response of 127.0.0.6
    elsif ($orsp eq A1276 && $zon =~ /^[A-Z0-9]{2}$/) {	# check Country Code Block
      if ($BBC &&
	  $zon eq $BBC->country_code_by_addr($IP) &&
	  grep($zon eq $_,@{$DNSBL->{BBC}})) {
	$validate = 1;
       	my $reason = "$zon ($cc2name->{$zon}) rejected";
	my $error = $DNSBL->{REJECT} || 'in my bad country list';
	my $expire = 2592000;			# 30 day expiration
	my $ipA = '127.0.0.6';
	my $netA = A1276;
	my $dnresp = $netA;
	_updateTpentry($tool,$reason,$error,$IP,$expire,$ipA,$dnresp,$netA,$zon,$contrib,$key,$tarpit,$DEBUG,$VERBOSE);
      } else {
	$zapped = "unblocked $zon ($cc2name->{$zon})";
      }
    }

# Reverse DNS
    elsif ($zon eq 'in-addr.arpa') {
      my $qbuf = question($dnsblIP.'.in-addr.arpa',T_PTR());
      my $response = query(\$qbuf,$timeout);
      $deadDNSBL{"$zon"} = 0;		# unconditional
      if ($response && scalar get16(\$response,6)) {	# good response and any ANSWER
	$zapped = 'reverse DNS OK';
      } else {
# block for any response failure
	$validate = 1;
	$dnresp = A1274;			# unconditional
	my $reason = ($response) ? 'no reverse DNS' : 'reverse DNS timeout';
	my $ipA = '127.0.0.4';
	my $netA = $dnresp;
	_updateTpentry($tool,$reason,$error,$IP,$expire,$ipA,$dnresp,$netA,$zon,$contrib,$key,$tarpit,$DEBUG,$VERBOSE);
      }
    }
# Regular DNSBL
    else {					# check DNSBL zone

      $zapped = 'unacceptable A record';	# trial value, cleared if validated below
      my $qbuf = question($dnsblIP.'.'.$zon,T_ANY);
      my $response = query(\$qbuf,$timeout);
      my ($aptr,$tptr,$auth_zone) = dns_ans(\$response);

      if ($@) {				# catastrophic failure
        $deadDNSBL{"$zon"} += 1;		# bump the retry count
        if ($exp < $now) {		# and zap record if expired
	  zap_pair($tool,$key,$tarpit,$contrib,$DEBUG,$VERBOSE,'expired (5)');
	  $zapped = 6;
        }
        next Record;
      }
      if ($response) {			# process exclusions
        $deadDNSBL{"$zon"} = 0 		# reset retry count
	  if $aptr && (@$aptr || $auth_zone eq $zon);

# if no A records and the zone is authoriatitive or 
# it answers and no SOA is present i.e. the zone exists -- like spamcop
        if (!($aptr && @$aptr) && ($auth_zone eq $zon || ! $auth_zone)) {
	  zap_pair($tool,$key,$tarpit,$contrib,$DEBUG,$VERBOSE,'cleared');
	  $zapped = 7;
	  next Record;
        }
      } else {		# no response
        if ($exp < $now) {
	  zap_pair($tool,$key,$tarpit,$contrib,$DEBUG,$VERBOSE,'expired (7)');
	  $zapped = 8;
        }
        next Record;
      }
# found an entry
      next Record unless @$aptr;			# skip if no 'A' records
# check the A records for acceptable codes until one is found
      my $netA;
    CheckZone:
      foreach $netA (@$aptr) {
        my $ipA = inet_ntoa($netA);
        foreach(keys %{$DNSBL->{"$zon"}->{accept}}) {
	  next unless ($_ eq $ipA);
  # found one, enter it in the tarpit
  # $netA contains the accepted code
  # find or create the TXT entry
	  $validate = 1;
	  my $reason = $DNSBL->{"$zon"}->{accept}->{"$_"};
        CheckTxt:
	  while(1) {
	    last CheckTxt unless @$tptr;
	    if (grep($_ =~ /spam/i,@$tptr)) {
	      foreach (@$tptr) {
	        next unless $_ =~ /spam/i;
	        $reason = $_;
	        last CheckTxt;
	      }
	    } elsif (grep($_ =~ /smtp/i,@$tptr)) {
	      foreach (@$tptr) {
	        next unless $_ =~ /smtp/i;
	        $reason = $_;
	        last CheckTxt;
	      }
	    } else {
	      $reason = $tptr->[0];
	    }
	    last CheckTxt;
	  }
	  last CheckZone
	    if _updateTpentry($tool,$reason,$error,$IP,$expire,$ipA,$dnresp,$netA,$zon,$contrib,$key,$tarpit,$DEBUG,$VERBOSE);
        }
      }
    }
    if ($validate) {
      $zapped = 0;
    } else {
      zap_pair($tool,$key,$tarpit,$contrib,$DEBUG,$VERBOSE,$zapped);
    }
  } continue {
    print "\n" if $VERBOSE;
    if ($DEBUG) {
      $cursor++;
    } elsif ( ! $zapped) {
      $cursor++;
    }
  }
  $tool->closedb;
  return '';
}

# update a tarpit entry time tag
#
# returns:	true if last CheckZone required, else false
#
# $tool		pointer to db object
# $reason	something like 'rejected, China'
# $error	something like 'in my bad country list' or 'see: http://whatsit.com?ip='
# $IP		lookup 12.34.56.78
# $expire	time in seconds, typically 30 days or less
# $ipA		response from remote DNS in text
# $dnresp	our packed netaddr response
# $netA		response from remote DNS - netaddr [inet_aton($ipA)]
# $zon		BBC, BLOCK, some.rbl.com
# $contrib	DB pointer
# $key		netaddr $IP - address of interest  [inet_aton($IP)]
# $tarpit	DB pointer

sub _updateTpentry {
  my($tool,$reason,$error,$IP,$expire,$ipA,$dnresp,$netA,$zon,$contrib,$key,$tarpit,$DEBUG,$VERBOSE) = @_;
	if ($reason =~ m|http://.+\..+| or $reason =~ /www\..+\..+/) {
	  $error = $reason;
	} else {
	  $error .= $IP		# append IP address if ends in http query string
		if $error =~ /\?.+=$/;
	  $error = $reason .', '. $error;
	}

	$expire += time;		# absolute expiration time
# create a text record of the form:
# response_code."\0".error_message."\0".dnsbl_code."\0".expire."\0".zone."\0".host

	if ($VERBOSE > 1) {
	  $_ =  qq|
zone response => $ipA
  record |. $IP .qq| => |. inet_ntoa($dnresp) . qq| $error
  timeout |. scalar localtime($expire) .q|

|;
	  print $_;

	}
	elsif ($VERBOSE) {
	  if ($DEBUG) {
	    print "would validate ";
	  } else {
	    print "validated ";
	  }
	}

	my $cz = 0;
	unless ($DEBUG) {
	  $_ = pack("a4 x A* x a4 x N x A*",$dnresp,$error,$netA,$expire,$zon);
	  unless ($tool->put($contrib,$key,$_)) {
	    $tool->sync($contrib);
	    unless ($tool->touch($tarpit,SerialEntry())) {	# and update the serial number
	      $tool->sync($tarpit);
	    }
	  }
	  $cz = 1;	# last CheckZone;
	}
	return $cz;
}

=item * @err=mailcheck($fh,\%MAILFILTER,\%DNSBL,\%default,\@NAignor)

This function extracts the sending mail server address, headers, and message
content from an "email message" that may [optionally] be PGP encoded. If an
IP address is successfully recovered, it is added to the 'tarpit' database
{SPMCNBL_DB_TARPIT} and the headers and message are added to the 'evidence'
database {SPMCNBL_DB_EVIDENCE}. See: config/sc_mailfilter.conf.sample for
configuration and details on optional settings.

  input:	file handle,
		config hash ptr,
		dnsbl config hash ptr,
		default config hash ptr,
		net object ptr,
  output:	empty array on success,
		(verbosity, err msg) on failure
	where verbosity is false on success,
	1,2,3, etc.... on failure

  my %default = (
	dbhome  => $environment,
	dbfile  => [$tarpit],
	txtfile => [$evidence],
	DEBUG   => $DEBUG,
	LIMIT   => $CHAR_SAVE_LIMIT, # characters
	PGPLIM	=> $CHAR_READ_LIMIT,
  );

=back

=cut

sub mailcheck {
  my($fh,$MAILFILTER,$DNSBL,$default,$NAignor) = @_;

  my $tarpit	= $default->{dbfile}->[0];
  my $archive	= $default->{dbfile}->[1];
  my $evidence	= $default->{txtfile}->[0];

# read up to 10,000 characters
  my $savlim	= $default->{LIMIT} || 10000;	# internal default is 1000
  my $readlim	= $default->{PGPLIM} || 5 * $savlim;
  my @lines;
  return (1,'no lines read')
	unless limitread($fh,\@lines,$readlim);

# close incomming connection
  dispose_of($fh);

  return(3,"startup blocked by DB watcher process")
	if -e $default->{dbhome} .'/'. 'blockedBYwatcher';

# skip the headers from local client
  my @discard;
  return (1,'no message found')
	unless skiphead(\@lines,\@discard);

# decrypt if Good Privacy
  my $err;
  while ($MAILFILTER->{PGP} && ref $MAILFILTER->{PGP} eq 'HASH') {
    my ($beg,$end) = is_pgp(\@lines,\$err);
    last if $err;

    $MAILFILTER->{PGP}->{Data} = array2string(\@lines,$beg,$end);
    my $plaintext = decrypt($MAILFILTER->{PGP});
    $MAILFILTER->{PGP}->{Data} = '';
    unless ($plaintext) {			# could not decode
      $err = 'could not decode PGP';
      last;
    }
    unless (string2array($plaintext,\@lines)) {
      $err = 'no plaintext 2 lines';
      last;
    }
    last;
  }
  if ($err) {
    if ($MAILFILTER->{PGP}->{Exceptions}) {
      @_ = (@discard, @lines);
      $err = 'Subject: '. $err ."\n\n". array2string(\@_);
      return(2,$err);
    } else {
      return(1,$err);
    }
  }

  undef @discard;

# extract headers
  my @headers;
  if ($MAILFILTER->{DIRTY}) {
    return (1,'no dirty headers')
	unless rfheaders(\@lines,\@headers);
  } else {
    return (1,'no headers')
	unless headers(\@lines,\@headers);
  }

# extract MTA's
  my @mtas;
  return (1,'no MTAs found')
	unless get_MTAs(\@headers,\@mtas);

# extract bad guy address
  my $noprivate = ($MAILFILTER->{NOPRIVATE})
	? 1 : 0;
  my $spamsource = firstremote(\@mtas,$MAILFILTER->{MXhosts},$noprivate);
  return (1,'no spam source found')
	unless $spamsource;

# punt if this address should be ignored
  return (1,'spam source ignored')
	if matchNetAddr($spamsource,$NAignor);

# stringify headers and message
  my $spam;
  return (1,'no evidence found')
	unless ($spam = array2string(\@lines));	# punt if no message

  $spam = substr($spam,0,$savlim)
	if length($spam > $savlim);
# tarpit this host address
  if ($default->{DEBUG}) {
    return (2,"Subject: $spamsource would add to $tarpit\n\n$spam");
  } else {
    (my $tool = new IPTables::IPv4::DBTarpit::Tools(%$default))
	or return(1,'could not open database environment, check your installation');
    my $netaddr = inet_aton($spamsource);  
    if ($archive && 
	! $tool->get($archive,$netaddr)) {
      $tool->closedb;
      return (2,"Subject: $spamsource not in 'archive'\n\n$evidence");
    }
    unless ($tool->put($evidence,$netaddr,$spam)) {
      $tool->sync($evidence);
      unless ($tool->touch($tarpit,$netaddr) ||	# add the tarpit entry
	  $tool->touch($tarpit,SerialEntry())) {	# and update the serial number
	$tool->sync($tarpit);
      }
    }
    $tool->closedb;
  }
  return ();
}

=head1 DEPENDENCIES

	NetAddr::IP
	Net::DNS::Codes
	Net::DNS::ToolKit
	Net::DNS::ToolKit
	Mail::SpamCannibal::GoodPrivacy
	Mail::SpamCannibal::BDBclient

=head1 EXPORT

	none by default

=head1 EXPORT_OK

	DO
	SerialEntry
	TarpitEntry
	DNSBL_Entry
	id
	question
	revIP   
	query   
	dns_ans 
	zone_def
	valid127
	validIP
	zap_one
	zap_pair
	job_died
	dbjob_chk
	dbjob_kill
	dbjob_recover
	unpack_contrib
	lookupIP
	list2NetAddr
	matchNetAddr
	BLcheck
	BLpreen
	mailcheck

=head1 COPYRIGHT

Copyright 2003, Michael Robinton <michael@bizsystems.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or 
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of 
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the  
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

=head1 AUTHOR

Michael Robinton <michael@bizsystems.com>

=head1 SEE ALSO

L<IPTables::IPv4::DBTarpit>,
L<Net::DNS::Codes>, L<Net::DNS::ToolKit>, L<Net::DNS::ToolKit::RR>,
L<Mail::SpamCannibal::DNSBLserver>, L<Mail::SpamCannibal::BDBaccess>

=cut

1;
