#!/usr/bin/perl
#
package Mail::SpamCannibal::PageIndex;
#
# cannibal.cgi or cannibal.plx
# link admin.cgi or admin.plx
#
# version 1.07, 9-29-03
#
# Copyright 2003, Michael Robinton <michael@bizsystems.com>
#   
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
use strict;
#use diagnostics;
use vars qw(%ftxt);

use Mail::SpamCannibal::ScriptSupport qw(
	DO
	query
	question
	lookupIP
	validIP
	valid127
);

#########################################################################
# Individual pages are put together by calling the html_cat routine.	#
# See: Mail::SpamCannibal::WebService &html_cat				#
#########################################################################

use Mail::SpamCannibal::WebService qw(
	sendhtml
	html_cat
	cookie_date
	get_query
);
use Mail::SpamCannibal::Session qw(
	decode
	sesswrap
);

my $CONFIG = DO '../config/sc_web.conf';

die "could not load config file"
	unless $CONFIG;

my ($admin,$sess,%extraheaders);
my $expire = $CONFIG->{expire} || '';
my %query = get_query();

# check for query from LaBrea client & convert if necessary
if ($query{query} =~ /(\d+\.\d+\.\d+\.\d+)/) {
  $query{page} = 'lookup';
  $query{lookup} = $1;
}

my $user;
if ($ENV{SCRIPT_FILENAME} && $ENV{SCRIPT_FILENAME} =~ m|/admin\..+$|) {
  $extraheaders{'Set-Cookie'} = 'SpamCannibal=on; path=/; expires='. cookie_date(1);
  if (($admin = $CONFIG->{wrapper}) &&
      -e $admin && -x $admin &&
      do {			# return true if good session instantiated
	if ($query{user} &&
	    defined $query{passwd} &&
	    ($_ = sesswrap("$admin newsess $query{user} $query{passwd}")) &&
	    $_ =~ /^OK\s+([\w-]+\.[\w-]+\.\d+\.\d+\.[\w-]+)/) {
	  $sess = $1;
	}
	elsif ($ENV{HTTP_COOKIE} && 
	    $ENV{HTTP_COOKIE} =~ /SpamCannibal=([\w-]+\.[\w-]+\.\d+\.\d+\.[\w-]+)/ &&
	    ($sess = $1) &&
	    ($_ = sesswrap("$admin chksess $sess $expire")) &&
	    $_ =~ /^OK\s*(.+)/ &&
	    ($user = $1)) {
	  1;
	} else {
	  0;
	}
      }
    ) {
    $extraheaders{'Set-Cookie'} = 'SpamCannibal='. $sess . 
	'; path=/; expires='. cookie_date(time + $CONFIG->{expire});
    $extraheaders{'Set-Cookie'} .= '; secure'
	if $CONFIG->{secure};
    $query{page} = 'ahome'
	unless $query{page};
  }
  else {
    $query{page} = 'login';
  }

  push @{$CONFIG->{static}}, @{$CONFIG->{admin}};
  if ($CONFIG->{secure} && ! $ENV{SSL_SERVER_CN}) {	# bail if not secure connection
    $query{page} = 'sorry';
  }
}
else {
  $query{page} = 'home'
	unless $query{page};
}

# %ftxt will contain a like hash of cached text and will already
# exist if there is a previous instantiation of this script

%ftxt = () unless %ftxt;

my $html = '';
my $pagerror = '';

PageGen:
while (1) {

# for static pages, just issue them
  my ($name,$nav);

  if ($admin) {		# use nav2 for admin
    $nav = (grep $query{page} =~ /^$_/,qw(sorry login))	# no nav bar for listed pages
	? '' : 'nav2';
  } else {
    $nav = 'nav';
  }

######	STATIC pages except 'home'

  foreach $name (@{$CONFIG->{static}}) {
    if ($query{page} =~ /^$name/) {
      foreach (qw(
		top
		logo2
		stats
		),
		$nav,
		$name,
	) {
        html_cat(\$html,$_,$CONFIG,\%ftxt);
      }
      $html .= $pagerror;
      last PageGen;
    }
  }

######	HOME

  if ($query{page} =~ /^home/) {
    foreach (qw(
	top
	logo1
	stats
	),
	'nav',
	'home',
        ) {
      html_cat(\$html,$_,$CONFIG,\%ftxt);
    }
    last PageGen;
  }

######	WHOIS

  if ($query{page} =~ /^whois/) {
    my $IP = ($query{whois} && $query{whois} =~ /(\d+\.\d+\.\d+\.\d+)/)
	? $1 : '';
    foreach (qw(
	top
	logo2
	stats
	),
	$nav,
	'whois',
        ) {
      html_cat(\$html,$_,$CONFIG,\%ftxt);
    }
    if ($IP) {
      if ($ENV{HTTP_REFERER} !~ /$ENV{SERVER_NAME}/i) {
	$html .= qq|
Due to the excessive load placed on our system, we have disabled the ability
for third party sites to query the Whois Proxy through the web
interface. Please enter your request manually.
|;
      } else {
	require Mail::SpamCannibal::WhoisIP;
	$html .= "Whois response for: <b>$IP</b><br><pre>\n";
	$html .= &Mail::SpamCannibal::WhoisIP::whoisIP($IP);
	$html .= "</pre>\n";
      }
    }
    last PageGen;
  }

######  CONTACT

  if ($query{page} =~ /^contact/) {
    die "email contact not configured" unless $CONFIG->{email};
    foreach (qw(
        top
        logo2
	stats
        ),
        $nav,
        ) {
      html_cat(\$html,$_,$CONFIG,\%ftxt);
    }
    $html .= q|
<blockquote>
<b>
|. ($ENV{REMOTE_HOST} || '') .' '. ($ENV{REMOTE_ADDR} || '') .q|<br>
</b>
</blockquote>
|;
    html_cat(\$html,'contact',$CONFIG,\%ftxt);
    last PageGen;
  }

######  SENDMSG

  if ($query{page} =~ /^sendmsg/) {
    die "email contact not configured" unless $CONFIG->{email};
    foreach (qw(
        top
        logo2 
	stats
        ),
        $nav,
        ) {
      html_cat(\$html,$_,$CONFIG,\%ftxt);
    }
    if ($ENV{HTTP_REFERER} !~ /$ENV{SERVER_NAME}/i) {
      $html .= q|
Automated send not allowed.
|;
    } else {
      require Mail::SpamCannibal::SMTPsend;
      if ($CONFIG->{altMXhosts}) {
	*Mail::SpamCannibal::SMTPsend::getMXhosts = sub {
	  return @{$CONFIG->{altMXhosts}};
	$_ = \*Mail::SpamCannibal::SMTPsend::getMXhosts; # suppress warning message
	}
      }
      $html .= q|
Message sent.
|;
      my $webmsg = qq|Subject: spamcannibal web contact

Remote Host:	$ENV{REMOTE_HOST}
Remote Addr:	$ENV{REMOTE_ADDR}

Email addr:	$query{email}
IP address:	$query{IP}

|;
      $_ = Mail::SpamCannibal::SMTPsend::sendmessage($webmsg . $query{message},$CONFIG->{email});
    }
    last PageGen;
  }

######	LOOKUP

  if ($query{page} =~ /^lookup/) {
    my $IP = ($query{lookup} && $query{lookup} =~ /(\d+\.\d+\.\d+\.\d+)/)
	? $1 : '';
    foreach (qw(
	top
	logo2
	stats
	),
	$nav,
	'lookup',
	) {
      html_cat(\$html,$_,$CONFIG,\%ftxt);
    }
    if ($IP) {
      if ($ENV{HTTP_REFERER} !~ /$ENV{SERVER_NAME}/i) {
	$html .= qq|
Automated lookups not allowed.
|;
      } else {
	require Mail::SpamCannibal::SiteConfig;
	my $sc = $CONFIG->{SiteConfig} || do { 
		require Mail::SpamCannibal::SiteConfig;
		new Mail::SpamCannibal::SiteConfig;
	};
	unless (exists $CONFIG->{bdbDAEMON}) {
	  $CONFIG->{bdbDAEMON} = $sc->{SPMCNBL_ENVIRONMENT} .'/bdbread';
	}

	my $substr = qq|<a href="#top" onClick="return(wIP('$IP'));" onMouseover="return(show('whois $IP'));" onMouseOut="return(off());">$IP</a>|;
	$html .= q|<script language=javascript1.1>
function wIP(ip) {
  document.LookUP.whois.value = ip;
  document.LookUP.action = location.pathname;
  document.LookUP.submit();
  return false;
}
</script>
<form name="LookUP" action="" method=POST>
<input type=hidden name=whois value="">
<input type=hidden name=page value=whois>
<table border=0><tr><td>Click for WhoisIP: |. $substr;

	if ($admin) {
	  $html .= q|
</td><td width=20>&nbsp;</td><td><table cellspacing=0 cellpadding=2 border=1>
<tr><td class=hot><a href="#top" class=hot onMouseOver="return(show('delete |. $IP .q|'));" onMouseOut="return(off());"
  onClick="self.location = location.pathname + '?page=delete&remove=' + '|. $IP .q|'; return false;">X</a></td></tr></table><td>delete</td>|;
	}
	my ($second,$text);
	if(ref $CONFIG->{bdbDAEMON}) {	# remote?
	  ($second,$text) = lookupIP($sc,$IP,@{$CONFIG->{bdbDAEMON}});
	} else {
	  ($second,$text) = lookupIP($sc,$IP,$CONFIG->{bdbDAEMON},0);
	}
	if($second) {		# if secondary db 'blcontrib'
	  $text =~ s|(http://([\w\.\-\?#&=/]+))|\<a href="$1"\>$2\</a\>|;
#	  $text =~ s|(http://([^\s]+))|\<a href="$1"\>$2\</a\>|;
	  $_ = "\n<p>\n". $text;
	}else {
	  $text =~ s/</&lt;/g;		# unmask html <
	  $text =~ s/>/*gt;/g;		# unmask html >
	  $text =~ s/$IP/$substr/g;
	  $_ = "\n<pre>\n". $text ."\n</pre>";
	}
	if ($admin && $text =~ /^not\s+in\s+\w+\s+database/) {
	  $html .= q|
<td width=20>&nbsp;</td><td><table cellspacing=0 cellpadding=2 border=1>
    <td class=cold><a href="#top" class=cold onMouseOver="return(show('tarpit |. $IP .q|'));" onMouseOut="return(off());"
  onClick="self.location = location.pathname + '?page=spamlst&host=' + '|. $IP .q|'; return false;">&#164;</td></tr></table><td>add to tarpit</td>|;
	}
	$html .= '</td></tr></table>';
	$html .= $_ . q|
</form>
|;
      }
    }
    last PageGen;
  }

######  LOGOUT

  if ($admin && $query{page} =~ /^logout/) {
    $_ = sesswrap("$admin rmvsess $sess");
    $query{page} = 'login';
    $extraheaders{'Set-Cookie'} = 'SpamCannibal=expired; path=/; expires='. cookie_date(1);
    next PageGen;
  }

######  USRUPD

  if ($admin && $query{page} =~ /^usrupd/) {
    $query{passwd} = '' unless $query{passwd};
    $query{passwd2} = '' unless $query{passwd2};
    $pagerror .= '<font size="+1" color=red>blank user name</font><br>'
	unless $query{newuser};
    $pagerror .= '<font size="+1" color=red>new passwords do not match</font><br>'
	if $query{passwd} ne $query{passwd2};
    unless ($pagerror) {
      $_ = sesswrap("$admin updpass $sess $expire $query{newuser} $query{passwd} $query{oldpasswd}");
      $pagerror .= '<font size="+1" color=red>' . $_ . '</font><br>'
	unless $_ =~ /^OK/;
    }
    if ($pagerror) {
# NOTE: see javascript entry at bottom of this page near </body> tag
      $query{page} = 'updpass';
    } else {
      $query{page} = 'ahome';
    }
    next PageGen;
  }

######  AHOME

  if ($admin && $query{page} =~ 'ahome') {
    foreach (qw(
	top
	logo2
	stats
	),
	$nav,
	) {
      html_cat(\$html,$_,$CONFIG,\%ftxt);
    }
    $sess =~ /^[\w-]+/;
    $user = $&;
    $html .= q|<center>
<table border=0>
<tr><td class=bld colspan=2>Access granted for:</td></tr>
<tr><td class=wht>User:</td><td class=bld>|. decode($user) .q|</td></tr>
<tr><td class=wht>Host:</td><td class=bld>|. ($ENV{REMOTE_HOST} || '<i>unknown</i>') .q|</td></tr>
<tr><td class=wht>IP:</td><td class=bld>|. ($ENV{REMOTE_ADDR} || '') .q|</td></tr>
<tr><td class=bld colspan=2>|. ($ENV{HTTP_USER_AGENT} || '<i>unknown</i>') .q|</td></tr>
</table>
</center>
|;
    last PageGen;
  }

######  SPAMADD

  if ($admin && $query{page} =~ /^spamadd/) {
    require Mail::SpamCannibal::ParseMessage;
    import Mail::SpamCannibal::ParseMessage qw(
	array2string
	string2array
    );
    my $host = validIP($query{host});
    $pagerror .= $query{host} .' <font size="+1" color=red>invalid host IP address</font><br>'
	unless $host;
    my @spam;
    $pagerror .= ' <font size="+1" color=red>no SPAM evidence entered</font><br>'
	unless $query{spam} =~ /\S+/ && string2array($query{spam},\@spam);

    if ($pagerror) {
      $query{page} = 'spamlst';
      next PageGen;
    }

    foreach(0..$#spam) {
      $spam[$_] = '>'. $spam[$_]
	if $spam[$_] eq '.' && $_ != $#spam;
    }
    push @spam, '.'
	if $spam[$#spam] ne '.';
    my $spam = array2string(\@spam);
    $_ = sesswrap("$admin insEVD $sess $expire $host",$spam);
    if ($_ =~ /^OK/) {
      $query{page} = 'lookup';
      $query{lookup} = $host;
    } else {
      $query{page} = 'spamlst';
      $pagerror = '<font size="+1" color=red>'. $_ .'</font><br>';
    }
    next PageGen;
  }

######  BLKADD

  if ($admin && $query{page} =~ /^blkadd/) {
    require Net::DNS::ToolKit;
    import Net::DNS::ToolKit qw(
	gethead
	get_ns
	inet_aton
	inet_ntoa
	ttlAlpha2Num
    );
    require Net::DNS::Codes;
    my $host = validIP($query{host});
    my $response = valid127($query{response});
    my $remote = validIP($query{remote});
    my $seconds = $query{expire} || 0;
    $seconds = ttlAlpha2Num($seconds) + time;
    $pagerror .= $query{host} .' <font size="+1" color=red>invalid host IP address</font><br>'
	unless $host;
    $pagerror .= $query{response} .' <font size="+1" color=red>invalid local DNSBL response IP</font><br>'
	unless $response && $response eq $query{response};
    $pagerror .= '<font size="+1" color=red>no TXT record string found</font><br>'
	unless $query{error};
    $pagerror .= $query{remote} .' <font size="+1" color=red>invalid remote DNSBL response IP</font><br>'
	unless $remote;
    $pagerror .= '<font size="+1" color=red> missing zone</font><br>'
	unless $query{zone};
    $pagerror .= $query{zone} .' <font size="+1" color=red>no NS records for this zone</font><br>'
	unless !$query{zone} || do {
		my @localns = get_ns();
		my $querybuf = question($query{zone},&Net::DNS::Codes::T_NS);
		my $resp = query(\$querybuf);
		if ($resp) {		# got answer
		  my ($off,$id,$qr,$opcode,$aa,$tc,$rd,$ra,$mbz,$ad,$cd,$rcode,
			$qdcount,$ancount,$nscount,$arcount)
			= gethead(\$resp);
		  $ancount;
		} else {
		  0;
		}
	};

    if ($pagerror) {
      $query{page} = 'blklist';
    } else {
      $_ = sesswrap(qq|$admin insBL $sess $expire $host $response "$query{error}" $remote $seconds $query{zone}|);
      if ($_ =~ /^OK/) {
	$query{page} = 'lookup';
	$query{lookup} = $host;
      } else {
	$query{page} = 'blklist';
	$pagerror = '<font size="+1" color=red>'. $_ .'</font><br>';
      }
    }
    next PageGen;
  }

######  DELETE

  if ($admin && $query{page} =~ /^delete/) {
    foreach (qw(
	top
	logo2
	stats
	),   
	$nav,
	) {  
      html_cat(\$html,$_,$CONFIG,\%ftxt);
    }
    $_ = sesswrap("$admin delete $sess $expire $query{remove}");
    if ($_ =~ /^OK/) {
      $html .= qq|<center><font size=5><b>$query{remove}</b></font> removed</center>\n|;
    } else {
      $html .= qq|$query{remove} $_\n|;
    }
    last PageGen;
  }

######  VIEW DB

  if ($admin && $query{page} =~ /^viewdb/) {
    require Mail::SpamCannibal::BDBclient;
    import Mail::SpamCannibal::BDBclient qw(
	dataquery
	retrieve
	INADDR_NONE
	inet_ntoa
    );
    foreach (qw(
	top
	logo2
	stats
	),
	$nav,
	) {
      html_cat(\$html,$_,$CONFIG,\%ftxt);
    }
    my $sc = $CONFIG->{SiteConfig} || do {
	require Mail::SpamCannibal::SiteConfig;
	new Mail::SpamCannibal::SiteConfig;
    };
    unless (exists $CONFIG->{bdbDAEMON}) {
	$CONFIG->{bdbDAEMON} = $sc->{SPMCNBL_ENVIRONMENT} .'/bdbread';
    }

    $html .= q|<script language=javascript1.1>
function dbvs(db,rn) {
  document.dbsel.action = location.pathname
  document.dbsel.datab.value = db;
  document.dbsel.recno.value = rn;
  document.dbsel.submit();
  return false;
}
function lIP(ip) {
  document.ViewDB.lookup.value = ip;
  document.ViewDB.action = location.pathname;
  document.ViewDB.submit();
  return false;
}
</script>
<form name=dbsel action="" method=POST onSubmit="return false;">
<input type=hidden name=page value=viewdb>
<input type=hidden name=datab value="">
<table cellspacing=0 cellpadding=10 border=0>
</script>
<tr align=center><td colspan=4 class=bld><font size="-1">Select DATABASE to view</font></td></tr>
<tr align=center>
|;
    
    my %records;
    foreach(	$sc->{SPMCNBL_DB_TARPIT},
		$sc->{SPMCNBL_DB_ARCHIVE},
		$sc->{SPMCNBL_DB_CONTRIB},
		$sc->{SPMCNBL_DB_EVIDENCE},
	) {
      $html .= q|<td class=bld>|;

      my($key,$val);
      if(ref $CONFIG->{bdbDAEMON}) {	# remote?
	($key,$val) =  dataquery(1,0,$_,@{$CONFIG->{bdbDAEMON}});
      } else {
	($key,$val) =  dataquery(1,0,$_,$CONFIG->{bdbDAEMON},0);
      }

      if (!$key || $key eq &INADDR_NONE()) {
	$val = '<font color=red>OFFLINE</font>';
	$records{$_} = 0;
      } else {
	$records{$_} = $val;		# save record count
      }

      $html .= $val .q| recs<br>
  <a href="#top" onClick="return(dbvs('|. $_ .q|','1'));" onMouseOver="return(show('|. (uc $_) .q|'));" onMouseOut="return(off());">|. $_ .q|</a></td>
|;
    }
    $html .= q|</tr>
</table>
|;
    unless ((my $db = $query{datab}) && 
	(my $rectop = $records{"$query{datab}"})) {	# no database view requested
      $html .= q|<input type=hidden name=recno value="">
</form>
|;
      last PageGen;

    } else {						# database view requested

      my $recno = $query{recno} || 1;
# bound record number
      $recno = $rectop - 254
	if $recno > $rectop - 254;
      $recno = 1
	if $recno < 1;

      my($count,@IPs);
      if(ref $CONFIG->{bdbDAEMON}) {	# remote?
	$count = retrieve(255,$recno,$db,\@IPs,@{$CONFIG->{bdbDAEMON}});
      } else {
	$count = retrieve(255,$recno,$db,\@IPs,$CONFIG->{bdbDAEMON},0);
      }

      unless ($count) {		# if database empty
	$html .= q|<input type=hidden name=recno value="">
</form>
|;
	last PageGen;
      }

      $html .= q|<table border=0><tr><td class=bld align=center colspan=6>database: |. $db .q|</td></tr>
<tr>
<td><table cellspacing=0 cellpadding=2 border=1><tr><td align=center class=gry><a href="#top"
      onClick="return(dbvs('|. $db .q|','1'));"
      onMouseOver="return(show('BEGIN'));" onMouseOut="return(off());">BEGIN</a></td></tr></table></td>
<td><table cellspacing=0 cellpadding=2 border=1><tr><td align=center class=gry>&lt;&lt;<a href="#top"
      onClick="return(dbvs('|. $db .q|','|. ($recno - 255) .q|'));"
      onMouseOver="return(show('PREVIOUS'));" onMouseOut="return(off());">PREVIOUS</a></td></tr></table></td>
<td><table cellspacing=0 cellpadding=2 border=1><tr><td align=center class=gry><a href="#top"
      onClick="return(dbvs('|. $db .q|','|. ($recno + 255) .q|'));"
      onMouseOver="return(show('NEXT'));" onMouseOut="return(off());">NEXT</a>&gt;&gt;</td></tr></table></td>
<td><table cellspacing=0 cellpadding=2 border=1><tr><td align=center class=gry><a href="#top"
      onClick="return(dbvs('|. $db .q|','|. ($rectop - 254) .q|'));"
      onMouseOver="return(show('END'));" onMouseOut="return(off());">END</a></td></tr></table></td>
<td><table cellspacing=0 cellpadding=2 border=1><tr><td nowrap align=center class=gry>&nbsp;&nbsp;<a href="#top"
      onClick="return(dbvs('|. $db .q|',document.dbsel.recno.value));"
      onMouseOver="return(show('GOTO'));" onMouseOut="return(off());">GOTO</a> &gt;</td></tr></table></td>
<td><input type=text name=recno></td>
</tr></table>
</form>
&nbsp;<font size="-1">record number |. $recno .q|</font>
<form name=ViewDB action="" method=POST>
<input type=hidden name=page value=lookup>
<input type=hidden name=lookup value="">
<table cellspacing=0 cellpadding=3 border=1>
|;

      for(my $i=0;$i <= $#IPs;$i += 5) {
	$html .= '<tr>';
	foreach(0..4) {
	  my $cell = '&nbsp;';
	  if ($IPs[$i+$_]) {
	    my $ip = inet_ntoa($IPs[$i+$_]);
	    $cell = ($ip =~ /^127\./) ? $ip :		# no link for internal addresses
	  	q|<a href="#top" onClick="return(lIP('|. $ip .q|'));" onMouseOver="return(show('|. $ip .q|'));" onMouseOut="return(off());">|. $ip .q|</a>|;
	  }
	  $html .= q|  <td>|. $cell . qq|</td>\n|;
	}
	$html .= qq|</tr>\n|;
      }
      $html .= q|</table>
</form>
|;
    }
    last PageGen;
  }

######  END page search
  $html .= q|<font size=6><b>Not Found</b></font>
<p>
The URL requested was not found on this server
|;
  last PageGen;	# oops!
}

# Special handling items
#	updpass
#	spamlst
#
$html .= q|
<script language=javascript1.1>
document.UpdPass.newuser.value = '|. $user .q|';
</script>
| if $query{page} =~ /^updpass/;

$html .= q|
<script language=javascript1.1>
document.SpamAdd.host.value = '|. $query{host} .q|';
</script>
| if $query{page} =~ spamlst &&
	validIP($query{host});

$html .= q|</body>
</html>
|;

sendhtml(\$html,\%extraheaders);

1;
