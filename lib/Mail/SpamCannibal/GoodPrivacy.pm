#!/usr/bin/perl
package Mail::SpamCannibal::GoodPrivacy;
use strict;
#use diagnostics;
use vars qw($VERSION @ISA @EXPORT_OK);

$VERSION = do { my @r = (q$Revision: 0.02 $ =~ /\d+/g); sprintf "%d."."%02d" x $#r, @r };

use Mail::SpamCannibal::ParseMessage qw(
	array2string
	string2array
);
require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(
	decrypt
	is_pgp
	whiteclean
);

=head1 NAME

  Mail::SpamCannibal::GoodPrivacy - PGP for spamcannibal mail

=head1 SYNOPSIS

  use Mail::SpamCannibal::GoodPrivacy;

  $plaintext = decrypt(\$hash);
	or	-- defaults shown
  $plaintext = decrypt(
	Data	  => $data,
	ExeFile	  => '/usr/local/bin/pgp',
	KeyPath	  => '.pgp',
	Password  => 'sometext',
	UserID	  => 'default userid',
	Version	  => '2.62',
  );

  ($begin,$end) = is_pgp(\@lines,\$err);
  $nullchar = whiteclean(\@array);
  $outstrng = whiteclean($instring);

=head1 DESCRIPTION

Mail::SpamCannibal::GoodPrivacy is a standardized 
wrapper around 'pgp2x', 'pgp6x', or 'gnupg'
that provides encryption and decryption for
IPTable::IPv4::DBTables::SpamCannibal.

Mail::SpamCannibal::GoodPrivacy has been tested using pgp-2.6.2g, pgp-6.5.8,
and gpg-1.2.2 on RSA keys generated by pgp-2.6.2g which are included with
this distribution.

Utilities to verify that a message has PGP encrypted content prior to
decryption so that plain text messages are not inadvertently passed to the
decrypt program;

=over 4

=item $plaintext = decrypt(\$hash);

  Decrypt an encoded message.

  input:	a hash or hash pointer
  return:	plaintext or '' on error

  %hash = (
	Data	  => $data,
	ExeFile	  => '/usr/local/bin/gpg',
	KeyPath	  => './',
	Password  => 'sometext',
	UserID	  => '',
	Version	  => '',
  );

    Data:	data to decrypt

    ExeFile:	location of executable
	i.e.	/usr/local/bin/pgp
		/usr/local/bin/gpg

	WARNING: use appropriate default
		 keyring names.

    KeyPath:    directory for keyrings

    Password:	password for decryption

    UserID:	Optional default user for decryption.

		The user 'name' or keyID

	i.e. 	'test' or

		E56C91B9 as displayed by
		pgp -kv ./keyrings/secring.pgp
		  or
		ENVGPGHOME=./keyrings gpg --list-secret-keys

    Version:	Version compliance (gpg only)
		(none) for standard gpg,
		2.6x and 6.x for pgp support

=cut

## test the input array

sub _testme {
  my $me = shift;
  # Data
  die "No data present\n"
	unless exists $me->{Data} && $me->{Data};

  # ExeFile
  die "PGP exe file missing or not executable by effective UID\n"
	unless exists $me->{ExeFile} && $me->{ExeFile} &&
	-e $me->{ExeFile} && -x $me->{ExeFile};

  # KeyPath
  $_ = $me->{KeyPath} || './';
  if ($_ eq '.') {
    $_ = './';
  } elsif ($_ ne './' && $_ ne '/') {
    chop $_ if $_ =~ m|/$|;
    $_ = './'.$_ unless $_ =~ m|^\.*/|;
  }
  die "Key path $_ does not exist\n"
	unless -d $_;
  $me->{KeyPath} = $_;

  # UserID
  $me->{UserID} = '' unless $me->{UserID};

  # Password
  $me->{Password} = '' unless $me->{Password};

  # Version
  $me->{Version} = '' unless $me->{Version};
}

sub decrypt {
  my $me = $_[0];
  return '' unless $me;
  $me = {@_} if @_ > 1;
  _testme($me);

  my $data = '';
  my $pgpcmd = '|'. $me->{ExeFile};
  $pgpcmd .= ' -u '. $me->{UserID} if $me->{UserID};
    
  if ($pgpcmd =~ m|/pgp[^/]*$|) {
    $pgpcmd .= ' -f +batchmode +force 2>/dev/null';
    $ENV{PGPPATH} = $me->{KeyPath};
    $ENV{PGPPASS} = $me->{Password};
  }
  elsif( $pgpcmd =~ m|/gpg[^/]*$|) {
    $data .= $me->{Password}."\n";
    $pgpcmd .= ' --pgp2' if $me->{Version} =~ /^2\./;
    $pgpcmd .= ' --pgp6' if $me->{Version} =~ /^6\./;
    $pgpcmd .= ' --decrypt --batch --passphrase-fd 0 2>/dev/null';
    $ENV{GNUPGHOME} = $me->{KeyPath};
  }
  else {
    die "could not find pgp or gpg executable\n";
  }

  $data .= $me->{Data};

  my $rv = '';
  my $pid = open(FROMCHILD, '-|');
  if($pid) {
    local $/;
    $rv = <FROMCHILD>;
    close FROMCHILD || ($rv = '');	# kid exited

  } else {	# child

    open(PGP,$pgpcmd) or die "could not exec pgpcmd\n";
    $|++;
    print PGP $data;
    close PGP;
    exit;
  }
  waitpid $pid,0;

  $ENV{PGPPASS} = '';
  return $rv;
}

=item ($begin,$end) = is_pgp(\@lines,\$err);

Test an array of lines to determine if they
represent a valid PGP encrypted message.

  input:	pointer to array of lines,
		[optional] pointer to 
		error return string

  returns:	() empty array on failure
    or	begin = pointer to -----BEGIN PGP
	end   = pointer to -----END
    for the input array

    $err will contain and empty string
	on success or a text message
	indicating the failure reason

	not an array ref
	signed cleartext
	no BEGIN PGP
	no blank line
	no armor text
	invalid armor
	no END
	
  i.e.	if (@_ = is_pgp(\@lines)) {
	  ($begin,$end) = @_;
	} else {
	  # sorry, not a PGP message
	}

=cut

#
# 1) find a begin statement:	-----BEGIN PGP
# 2) that is not clear signed:	-----BEGIN PGP SIGN
# 3) ignore any number lines:	comment (not case sensitive)
#    starting like this		version (not case sensitive
# 4) find one and only one:	(blank line)
# 5) find 1 or more rad64:	lines
# 6) find and end statement:	-----END

sub is_pgp {
  my($ap,$ep) = @_;
  if (ref $ep) {
    $$ep = '';
  } else {
    undef $ep;
  }
  unless (ref $ap) {
    $$ep = 'not an array ref' if $ep;
    return ();
  }
  my $TOPMSG	= '-----BEGIN PGP';		# beginning of PGP
  my $SIGMSG	= $TOPMSG . ' SIGNED';	# clear signed
  my $notRAD64	= "[^a-zA-Z0-9/\+\=]";
  my $END	= '-----END';

  my $noblank = 1;
  my $noarmor = 1;
  my $ptr;
  foreach(0..$#{$ap}) {
    unless (defined $ptr) {			# begin found??
      next unless $ap->[$_] =~ /$TOPMSG/o;
# if SIGNED message found, this is cleartext, punt!
      if ($ap->[$_] =~ /$SIGMSG/o) {
	$ptr = -1;
	last;
      }
      $ptr = $_;		# defined, pointer to message start
    }
    elsif ($noblank) {				# drop comments, check for 1 blank line
      next if	$ap->[$_] =~ /^comment/i ||
		$ap->[$_] =~ /^version/i;	# skip comments
      last if $ap->[$_] =~ /\S/;		# PUNT, not blank line
      $noblank = undef;
    }
    elsif ($noarmor) {				# must find ascii armor
      last if $ap->[$_] !~ /\S/ ||
	      $ap->[$_] =~ m|$notRAD64|o ;	# PUNT, not ascii armor
      $noarmor = 0;
    } else {					# searching for end
      return ($ptr,$_)
	if $ap->[$_] =~ /^$END/o;		# FOUND end, GOOD exit
      if ($ap->[$_] !~ /\S/ ||
	  $ap->[$_] =~ m|$notRAD64|o) {		# PUNT, not ascii armor;
	$noarmor = 2;
	last;
      }
    }
  }
  if ($ep) {
    unless (defined $ptr) {
      $$ep = 'no BEGIN';
    } elsif ($ptr < 0) {
      $$ep = 'signed cleartext';
    } elsif ($noblank) {
      $$ep = 'no blank line';
    } elsif ($noarmor == 1) {
      $$ep = 'no armor text'
    } elsif ($noarmor == 2) {
      $$ep = 'invalid armor'
    } else {
      $$ep = 'no END';
    }
  }
  return ();					# did not find PGP message
}

=item $nullchar = whiteclean(\@array);

See below:

=item $outstrng = whiteclean($string);

Cleans trailing whitespace from a text string or an array of text lines.

If the input is an array pointer to an array of text lines, cleans the lines
of trailing whitespace in place.

If the input is a string, returns a string with trailing whitespace removed.

  input:	array pointer
	   or	string
  returns:	'' if input = ARRAY
		$outstring
	   if the input was a string

=back

=cut

sub _whiteAcln {
  my $ap = shift;
  foreach(0..$#{$ap}) {
    $ap->[$_] =~ s/\s+$//g;
  }
}

sub whiteclean($) {
  my $thing = shift;
  my $rv = '';
  if (ref $thing eq 'ARRAY') {
    _whiteAcln($thing);
    return '';
  }
  @_ = split(/\n/,$thing);
  _whiteAcln(\@_);
  array2string(\@_);
}

1;
__END__

=head1 DEPENDENCIES

  Mail::SpamCannibal::ParseMessage
	and
  You must install at least one of the following
  on your system to use this module.

=over 2

=item PGP

  Recommend versions of freeware from:
  http://www.pl.pgpi.org/versions/freeware.shtml

  in the US:	PGP 2.6.2g, the "rebel" version
  ftp://sunsite.smc.univie.ac.at/pub/crypto/cypherpunks/pgp/pgp262/pgp262g.zip

  outside US:	PGP 2.6.3i
  http://www.pgpi.org/
  i.e. pgp263is.tar.gz + pgp263i.patch
	or
  outside US:	PGP 6.5.8
  http://www.pgpi.org/
  i.e. 'pgpsrc658unix-gnu.tar.gz',
	PGPcmdln_6.5.8.Lnx_FW.tar.gz,
    or	PGPcmdln_6.5.8.Lnx_FW.rpm.tar

  2.6.2 rebel was the default used to 
  develop this module.

=item GnuPG

  http://www.gnupg.org/

If you plan to user PGP 2.6x or 6.x compatibility modes and you are in a
country where there are not patent restrictions, then you will also need to
download:

  ftp://ftp.gnupg.dk/pub/contrib-dk/iodea.c.gz

and place it in the SRC/gnupg-1.x.x/cipher directory.

=item NOTE:	in all cases the default key file required.

	PGP 2.6.x	pubring.pgp, secring.pgp
	PGP 6.5.8	pubring.pkr, secring.skr
	GnuPG		pubring.gpg, secring.gpg

=back

=head1 EXPORT_OK

        decrypt
        is_pgp
        whiteclean

=head1 AUTHOR

Michael Robinton <michael@bizsystems.com>

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

=head1 SEE ALSO

perl(1)

=cut

1;
