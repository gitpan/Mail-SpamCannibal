# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.
# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..385\n"; }
END {print "not ok 1\n" unless $loaded;}

use Cwd;
use CTest;

$TCTEST		= 'Mail::SpamCannibal::DNSBLserver::CTest';
$loaded = 1;
print "ok 1\n";
######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

$test = 2;

umask 007;
foreach my $dir (qw(tmp tmp.dbhome tmp.bogus)) {
  if (-d $dir) {         # clean up previous test runs
    opendir(T,$dir);
    @_ = grep(!/^\./, readdir(T));
    closedir T;
    foreach(@_) {
      unlink "$dir/$_";
    }
    rmdir $dir or die "COULD NOT REMOVE $dir DIRECTORY\n";
  }
  unlink $dir if -e $dir;       # remove files of this name as well
}

sub ok {
  print "ok $test\n";
  ++$test;
}

my $localdir = cwd();
my $testdir = $localdir .'/tmp.dbhome';
mkdir $testdir;

sub fqdn {
  (gethostbyname(&{"${TCTEST}::t_short"}()))[0];
}

my %args;
my $extra;
my %expect;

# input array @_ used in child process after } else {
sub dumpargs {
  %args = ();
  $extra = '';
  if (open(FROMCHILD, "-|")) {
    while (my $record = <FROMCHILD>) { 
      if ($record =~ /(\S+)\s+=>\s+(\S+)/) {
# keep for testing
# print "$1	=> '$2',\n";
        $args{$1} = $2;
      } else {
        $extra .= $record;
# print "rec => $record\n";
      }
    }
  } else {
# program name is always argv[0]
    unless (open STDERR, '>&STDOUT') {
      print "can't dup STDERR to /dev/null: $!";
      exit;
    }
    &{"${TCTEST}::t_main"}('CTest',@_);
    exit;
  }
  close FROMCHILD;
}

sub checkargs {
  my $y = keys %args;
  my $x = keys %expect;
  print "key count expect = $x\n".
	"key count found  = $y\nnot "
	unless $x == $y;
  &ok;
  foreach(sort keys %expect) {
    if (!exists $args{$_}) {
      print "key '$_' not found\nnot ";
    }
    elsif (	($args{$_} =~ /\D/ && $args{$_} ne $expect{$_}) ||
		($args{$_} !~ /\D/ && $args{$_} != $expect{$_})) {
      print "$_ is $args{$_}, should be $expect{$_}\nnot ";
    }
    &ok;
  }
}

sub dumpnchk {
  dumpargs(@_);
  checkargs;
}

# check contents of extra print variables
sub checkextra {
  my ($x) = @_;
  if($x) {
    print "UNMATCHED RETURN TEXT\n$extra\nnot "
	unless $extra =~ /^$x/;
  } else {
    print "UNEXPECTED RETURN TEXT\n$extra\nnot "
	if $extra;
  }
  &ok;
}

## test 2-22 T flag only
my @x = qw(-T);
%expect = (
-r      => '/var/run/dbtarpit',
-i      => 'tarpit',
-j      => 'blcontrib',
-k      => 'evidence',
block   => '0',
-L	=> '200000cps,',
eflag   => 'undefined',
dflag   => '0',
oflag   => '0',
loglvl  => '0',
port    => '53',
Tflag   => '1',
promiscuous => '0',
zone    => fqdn(),
Zflag   => '0',
contact => 'root.'. fqdn(),
uflag   => '43200',
yflag   => '3600',
xflag   => '86400',
tflag   => '10800',
);
dumpnchk(@x);

## test 23 - check extra text
checkextra('local records');

## test 24-44 T d
$expect{dflag} = 1;
@x = qw(-T -d);
dumpnchk(@x);

## test 45 - check extra text
checkextra('local records');

## test 46-66 - dflag is active with oflag
$expect{oflag} = 1;
@x = qw(-T -o);
dumpnchk(@x);

## test 67 - check extra text
print "got:\n$extra\nit should contain:\nlocal records:\n\nnot "
	unless $extra =~ /local records:\n/;
&ok;

# clear previous test flags to initial state
$expect{dflag} = $expect{oflag} = 0;

## test 68-88 lflag
$expect{loglvl} = 1;
@x = qw(-T -l);
dumpnchk(@x);

## test 89 - check extra text
checkextra('local records:');

## test 90-110 vflag, same as lflag
$expect{loglvl} = 2;
@x = qw(-T -v);
dumpnchk(@x);

## test 111 - check extra text
checkextra('local records:');

## test 112-132 both v & l is verbose
$expect{loglvl} = 3;
@x = qw(-T -v -l);
dumpnchk(@x);

## test 133 - check extra text
checkextra('local records:');

# clear previous test flags to initial state
$expect{loglvl} = 0;

## test 134 get help string
@x = qw(-T -?);
dumpargs(@x);    
checkextra('Usage: dnsbls <options>');

## test 135 version ID
@x = qw(-T -V);  
dumpargs(@x);    
checkextra('dnsbls');

## test 136-156 db home dir
$expect{'-r'} = '/somewhere/else';
@x = qw(-T -r /somewhere/else);
dumpnchk(@x);

## test 157 - check extra text
checkextra('local records:'); 

## test 158-178 db primary file
$expect{'-i'} = 'primary';
@x = qw(-T -r /somewhere/else -i primary);
dumpnchk(@x);

## test 179 - check extra text
checkextra('local records:'); 

## test 180-200 db secondary file
$expect{'-j'} = 'secondary';        
@x = qw(-T -r /somewhere/else -i primary -j secondary);
dumpnchk(@x);

## test 201 - check extra text
checkextra('local records:'); 

# clear previous test flags to initial state
$expect{'-r'} = '/var/run/dbtarpit';
$expect{'-i'} = 'tarpit';
$expect{'-j'} = 'blcontrib';

## test 202-222 final check should be same as beginning
@x = qw(-T);
dumpnchk(@x);

## test 223 - check extra text
checkextra('local records:');     

## test 224 - check failed directory, not there
@x = ('-r', "${localdir}/xxx", '-d', '-o');
dumpargs(@x);
checkextra("${localdir}/xxx");

## test 225 - check failed directory, not a directory
@x = ('-r', "${localdir}/MANIFEST", '-d', '-o');
dumpargs(@x);
checkextra("${localdir}/MANIFEST");

## test 226 get help string using -h
@x = qw(-T -h);
dumpargs(@x);
checkextra('Usage: dnsbls <options>');

## test 227 check error name server missing
@x = ('-r', $testdir);
dumpargs(@x);
checkextra('Error: -n');

## test 228 add only address
@x = qw( -a 12.34.56.78);
dumpargs(@x);
checkextra('Error: 0,');

## test 229-250 add nameserver and address
$expect{NS} = 'ns.xx.yy.zz.com';
@x = qw( -T -n ns.xx.yy.zz.com -a 11.22.33.44 );
dumpnchk(@x);

## test 251 check name server info
checkextra('local records:
	11.22.33.44');

delete $expect{NS};
## test 252 add only mx priority
@x = qw( -m 50);   
dumpargs(@x);
checkextra('Error: -n');

## test 253-274 add mail server and address with -a addition
$expect{MX} = 50;
@x = qw( -T -n mx.yy.zz.com -m 50 -a 44.33.22.11 );
dumpnchk(@x);

## test 275 check mx server info
checkextra('local records:
	44.33.22.11');

## test 276-297 add mail server and address with -m addition (after ns record is stored)
$expect{MX} = 555;
@x = qw( -T -n mx.yy.zz.com -a 44.33.22.11 -m 555);
dumpnchk(@x);

## test 298 check mx server info
checkextra('local records:
	44.33.22.11');

## test 299-321 add mail server with dangling pickup, don't check unknown IP address
$expect{NS} = 'ns.aa.bb.net';
$expect{MX} = 66;
@x = (qw( -T -n ns.aa.bb.net -a 55.11.33.22 -n ), fqdn(), qw( -m 66 ));
dumpnchk(@x);

## test 322 check ns server info only
checkextra('local records:
	55.11.33.22');

## test 323-343	revert to start
delete $expect{NS};
delete $expect{MX};
dumpnchk('-T');

## test 344-364	new evidence file
$expect{'-k'} = 'stuff';
@x = qw( -T -k stuff );
dumpnchk(@x);

## test 365-385 revert to start with Z = 1
$expect{'-k'} = 'evidence';
$expect{Zflag} = 1;
@x = qw( -T -Z );
dumpnchk(@x);
