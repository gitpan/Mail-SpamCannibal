package Mail::SpamCannibal::DNSBLserver::CTest;

#use 5.006;
use strict;
#use warnings;
use Carp;

use vars qw(@ISA $VERSION);

require Exporter;
require DynaLoader;
use AutoLoader;

@ISA = qw(Exporter DynaLoader);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

$VERSION = do './DNSBLserver.pm';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.  If a constant is not found then control is passed
    # to the AUTOLOAD in AutoLoader.

    my $constname;
    our $AUTOLOAD;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "& not defined" if $constname eq 'constant';
    my $val = constant($constname, @_ ? $_[0] : 0);
    if ($! != 0) {
	if ($! =~ /Invalid/ || $!{EINVAL}) {
	    $AutoLoader::AUTOLOAD = $AUTOLOAD;
	    goto &AutoLoader::AUTOLOAD;
	}
	else {
	    croak "Your vendor has not defined CTest macro $constname";
	}
    }
    {
	no strict 'refs';
	# Fixed between 5.005_53 and 5.005_61
	if ($] >= 5.00561) {
	    *$AUTOLOAD = sub () { $val };
	}
	else {
	    *$AUTOLOAD = sub { $val };
	}
    }
    goto &$AUTOLOAD;
}

bootstrap Mail::SpamCannibal::DNSBLserver::CTest $VERSION;

# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__

# Below is stub documentation for your module. You better edit it!

=head1 NAME

CTest - Perl extension for testing local 'C' routines

=head1 SYNOPSIS

  use CTest;

=head1 DESCRIPTION

This module consists of various test routines to exercise the subroutines in
the the 'C' pieces for F<dnsbls>

=over 4

=item * $rv=t_main(qw(program_name args, arg2,..., argN);

  input:	program name
		-d
		-f etc... see readme
  output:	number of arguments passed

=item * t_setsig();

  set the signal handler. 
  test routine should issue SIGINT 
  to child and catch resulting text

=item * t_set_parent(val);

  set the value of "parent"
  return the previous value

=item * t_set_qflag(val);

  set the value of "qflag"
  return the previous value

=item * $pid = t_pidrun()

  input:	none
  output:	pid found in pid file

  see t_chk4pid below

=item * t_savpid(path2pidfile)

  input:	path to pid file
  output:	none

  saves the pid of the current process
  in the pid file (path2pidfile)

=item * $pidpath = t_chk4pid(path)

  input:	path to pid file
  output:	undef or path to pid file

  checks for a process running with the pid
  found in "path". If the process is running
  return undef, otherwise return the "path".
  Always places the "pid" found in pid file
  into the variable "pidrun".

=item * $pidpath = t_pidpath();

  input:	none
  output:	current pidpath/file

=item * $err = t_init(home,...);

  input:	dbhome
		db file name
		secondary db file name (optional)
  output:	0 or error code

=item * $err = t_dump(which);

  input:	0  = primary db
		nz = secondary db
  output:	0 or error code

  prints database to STDOUT in the format
	dot.quad.addr => timestamp

=item * t_close();

  input:	none
  output:	none

  close the database files and environment

=item * $data = t_get(which,addr);

  input:	0  = primary db
		nz = secondary db
  output:	data (long)
		or undef if not there

=item * $short_hostname = t_short();

  input:	none
  output:	short host name

=item * $rv = t_munge(fd,bp,msglen,is_tcp)

  input:	handle number, [fileno(FD)]
		pointer buffer,
		length of buffer,
		tcp flag

  output:	number of bytes processed,
		-1 on error

  NOTES: is_tcp
  Setting is_tcp true forces TCP mode in the ns.c
  is_tcp tells ns.c how to process the requests 
  (TCP or UDP) and specifically how to process AXFR 
  requests so we can test all of the program branches.
 
  is_tcp  = 0  use UDP
  is_tcp  = 1  use TCP, AXFR in one message if possible
  is_tcp  = 2  use TCP, AXFR in two messages. The first 
               message contains all overhead records, SOA, 
               NS, MX and local host stuff. The second 
               message contains all numeric A & TXT records  
               or as many as will fit.
  is_tcp >= 3  The first record is the same as is_tcp 2. 
               Each additional record contains an A + TXT 
               record pair for a particular numeric record, 
               with the last record containing only the SOA

=item * $rv = t_cmdline(cmd,stuff);

  input:	one of z,n,m,a,b,c,e,L,I,Z,
		parameter
  output:	true on success else false

  SEE:		command line parameters for
		rblns -z -n -m -a -b -c -e -Z

B<L> sets the name of the local host. If the zone name has been
set already then the zoneEQlocal flag is set appropriately. If local host
name is already set when the zone name is set, zoneEQlocal will again be set
appropriately.

B<I> sets the IP address of the local host
		
=item * $rv = t_set_resp(zero,stdResp);

  input:	ipaddr for zero,
		ipaddr for stdResp
  output:	true on success,
		else undef

  Set the ip address for db access

=item * $rv = t_cmp_serial(s1,s2);

  input:	zone serial number pair
  returns:	 0	s1 = s2
		-1	s1 < s2
		 1	s1 > s2
		>1	 undefined

=item * $rv = t_name_skip(buf);

  input:	buffer of characters/numbers
  returns:	integer offset from begining
		of buffer past dn names

=back

=head1 EXPORT

None

=head1 AUTHOR

Michael Robinton <michael@bizsystems.com>

=head1 See also: files in subdirectory ./t

=cut
