use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

###########################################################
##          if built from a parent directory,             #
##      at install, the parent Makefile must execute      #
##                                                        #
##  @cd SpamCannibal && $(MAKE) install_daemon $(PASTHRU) #
##  @cd SpamCannibal && $(MAKE) clean_CTest $(PASTHRU)    #
##                                                        #
###########################################################

use Config;
use vars qw($CONFIG);
use Cwd qw(abs_path);
use IPTables::IPv4::DBTarpit::Inst qw(:all);

my $conf = 'config.db';
my $home = abs_path('./');
my $localconf = $home .'/'. $conf;

my $configtxt;

if ((caller)[1]) {
  hard_fail("Do not MAKE ". __PACKAGE__ ." as a sibling process
it contains directory sensitive components.");
}

$configtxt = do 'inst/dialog.pl';
$CONFIG = do 'config.db';

my($uid,$gid) = (getpwnam($CONFIG->{SPAMCANNIBAL_USER}))[2,3];

hard_fail('Can not find password file entry for user '. $CONFIG->{SPAMCANNIBAL_USER} .'
You must create the user and directory structure
before running this installation procedure.
') unless $CONFIG->{SPAMCANNIBAL_USER} && $uid && $gid;

# pull in pod pages for external support modules
my %xmodules = (
  'Geo::IP::PurePerl'			=> 'Geo-IP-PurePerl',
  'Geo::CountryFlags'			=> 'Geo-CountryFlags',
  'IPTables::IPv4::DBTarpit'		=> 'dbtarpit',
  'IPTables::IPv4::DBTarpit::Tools'	=> 'IPTables-IPv4-DBTarpit-Tools',
  'IPTables::IPv4::DBTarpit::Inst'	=> 'IPTables-IPv4-DBTarpit-Tools-Inst',
  'LaBrea::Tarpit'			=> 'LaBrea-Tarpit',
  'LaBrea::Tarpit::Report'		=> 'LaBrea-Tarpit-Report',
  'Net::DNS::Codes'			=> 'Net-DNS-Codes',
  'Net::DNS::ToolKit'			=> 'Net-DNS-ToolKit',
  'Net::DNS::ToolKit::RR'		=> 'Net-DNS-ToolKit-RR',
  'Net::DNS::ToolKit::RR::Template'	=> 'Net-DNS-ToolKit-RR-Template',
  'Net::DNS::ToolKit::Question'		=> 'Net-DNS-ToolKit-Question',
  'Net::DNSBL::MultiDaemon'		=> 'Net-DNSBL-MultiDaemon',
  'Net::SMTP'				=> 'Net-SMTP',
  'Net::Whois::IP'			=> 'Net-Whois-IP',
  'NetAddr::IP'				=> 'NetAddr-IP',
  'Proc::PidUtil'			=> 'Proc-PidUtil',
  'Sys::Hostname::FQDN'			=> 'Sys-Hostname-FQDN',
);

my %xpmfiles;
foreach(keys %xmodules) {
  next unless eval "require $_";
  (my $pmf = $_) =~ s|::|/|g;
  $pmf .= '.pm';
  $xpmfiles{"$INC{$pmf}"} = 'docs/'. $xmodules{$_} . '.html';
}

my %makeparms = (
   'NAME'         => 'Mail::SpamCannibal',
   'VERSION_FROM' => 'SpamCannibal.pm',		# finds $VERSION
   'PREREQ_PM'	  => {
			'IPTables::IPv4::DBTarpit' => '0.23',
			'Geo::IP::PurePerl'	=> '1.10',
			'Sys::Hostname::FQDN'	=> '0.06',
			'Net::DNS::Codes'	=> '0.08',
			'Net::DNS::ToolKit'	=> '0.15',
			'NetAddr::IP'		=> '0.35',
			'Net::DNSBL::MultiDaemon' => '0.03',
			'Net::SMTP'		=> '2.10',
			'Net::Whois::IP'	=> '0.35',
			'MIME::Base64'		=> '2.00',
			'Digest::MD5'		=> '2.00',
			'Test::Harness'		=> '2.01',
			'Test::Simple'		=> '0.42',
			'Unix::Syslog'		=> '0.97',
			'Proc::PidUtil'		=> '0.06',
		  },
   'PM'		  => {  'SpamCannibal.pm' => '$(INST_LIBDIR)/SpamCannibal.pm',
			'SiteConfig.pm' => '$(INST_LIB)/Mail/SpamCannibal/SiteConfig.pm',
			'lib/Mail/SpamCannibal/GoodPrivacy.pm'
				=> '$(INST_LIB)/Mail/SpamCannibal/GoodPrivacy.pm',
			'lib/Mail/SpamCannibal/ParseMessage.pm'
				=> '$(INST_LIB)/Mail/SpamCannibal/ParseMessage.pm',
			'lib/Mail/SpamCannibal/SMTPsend.pm'
				=> '$(INST_LIB)/Mail/SpamCannibal/SMTPsend.pm',
			'lib/Mail/SpamCannibal/ScriptSupport.pm'
				=> '$(INST_LIB)/Mail/SpamCannibal/ScriptSupport.pm',
			'lib/Mail/SpamCannibal/WebService.pm'
				=> '$(INST_LIB)/Mail/SpamCannibal/WebService.pm',
			'lib/Mail/SpamCannibal/WhoisIP.pm'
				=> '$(INST_LIB)/Mail/SpamCannibal/WhoisIP.pm',
			'lib/Mail/SpamCannibal/Password.pm'
				=> '$(INST_LIB)/Mail/SpamCannibal/Password.pm',
			'lib/Mail/SpamCannibal/Session.pm'
				=> '$(INST_LIB)/Mail/SpamCannibal/Session.pm',
			'lib/Mail/SpamCannibal/PidUtil.pm'
				=> '$(INST_LIB)/Mail/SpamCannibal/PidUtil.pm',
			'lib/Mail/SpamCannibal/LaBreaDaemon.pm'
				=> '$(INST_LIB)/Mail/SpamCannibal/LaBreaDaemon.pm',
			'lib/Mail/SpamCannibal/IP2ccFlag.pm'
				=> '$(INST_LIB)/Mail/SpamCannibal/IP2ccFlag.pm',
		  },
   'MAN3PODS'	  => {	'SpamCannibal.pm' => '$(INST_MAN3DIR)/Mail::SpamCannibal.$(MAN3EXT)',
			'SiteConfig.pm' => '$(INST_MAN3DIR)/Mail::SpamCannibal::SiteConfig.$(MAN3EXT)',
			'lib/Mail/SpamCannibal/GoodPrivacy.pm'
				=> '$(INST_MAN3DIR)/Mail::SpamCannibal::GoodPrivacy.$(MAN3EXT)',
			'lib/Mail/SpamCannibal/ParseMessage.pm'
				=> '$(INST_MAN3DIR)/Mail::SpamCannibal::ParseMessage.$(MAN3EXT)',
			'lib/Mail/SpamCannibal/SMTPsend.pm'
				=> '$(INST_MAN3DIR)/Mail::SpamCannibal::SMTPsend.$(MAN3EXT)',
			'lib/Mail/SpamCannibal/ScriptSupport.pm'
				=> '$(INST_MAN3DIR)/Mail::SpamCannibal::ScriptSupport.$(MAN3EXT)',
			'lib/Mail/SpamCannibal/WebService.pm'
				=> '$(INST_MAN3DIR)/Mail::SpamCannibal::WebService.$(MAN3EXT)',
			'lib/Mail/SpamCannibal/WhoisIP.pm'
				=> '$(INST_MAN3DIR)/Mail::SpamCannibal::WhoisIP.$(MAN3EXT)',
			'lib/Mail/SpamCannibal/Password.pm'
				=> '$(INST_MAN3DIR)/Mail::SpamCannibal::Password.$(MAN3EXT)',
			'lib/Mail/SpamCannibal/Session.pm'
				=> '$(INST_MAN3DIR)/Mail::SpamCannibal::Session.$(MAN3EXT)',
			'lib/Mail/SpamCannibal/PidUtil.pm'
				=> '$(INST_MAN3DIR)/Mail::SpamCannibal::PidUtil.$(MAN3EXT)',
			'lib/Mail/SpamCannibal/LaBreaDaemon.pm'
				=> '$(INST_MAN3DIR)/Mail::SpamCannibal::LaBreaDaemon.$(MAN3EXT)',
			'lib/Mail/SpamCannibal/IP2ccFlag.pm'
				=> '$(INST_MAN3DIR)/Mail::SpamCannibal::IP2ccFlag.$(MAN3EXT)',
		  },
   'INST_HTMLLIBDIR'		=> 'docs',
   'INSTALLHTMLSITELIBDIR'	=> $CONFIG->{SPAMCANNIBAL_HOME} .'/public_html/docs',
   'HTMLLIBPODS'	=> { (%xpmfiles),	# include foreign pm's for doc tree
		(	'pods/scripts.pod'		=> 'docs/scripts.html',
			'pods/index.pod'		=> 'docs/index.html',
			'pods/INSTALL.pod'		=> 'docs/install.html',
			'pods/recover.pod'		=> 'docs/recover.html',
			'pods/howitworks.pod'		=> 'docs/howitworks.html',
			'pods/howtouse.pod'		=> 'docs/howtouse.html',
			'DNSBLserver/dnsbls.pod'	=> 'docs/dnsbls.html',
			'BDBaccess/bdbaccess.pod'	=> 'docs/bdbaccess.html',
			'SpamCannibal.pm'		=> 'docs/SpamCannibal.html',
			'SiteConfig.pm'			=> 'docs/SiteConfig.html',
			'BDBaccess/lib/Mail/SpamCannibal/BDBclient.pm' => 'docs/BDBclient.html',
			'lib/Mail/SpamCannibal/GoodPrivacy.pm'	 => 'docs/GoodPrivacy.html',
			'lib/Mail/SpamCannibal/ScriptSupport.pm' => 'docs/ScriptSupport.html',
			'lib/Mail/SpamCannibal/ParseMessage.pm'	 => 'docs/ParseMessage.html',
			'lib/Mail/SpamCannibal/SMTPsend.pm'	 => 'docs/SMTPsend.html',
			'lib/Mail/SpamCannibal/WebService.pm'	 => 'docs/WebService.html',
			'lib/Mail/SpamCannibal/Password.pm'	 => 'docs/Password.html',
			'lib/Mail/SpamCannibal/WhoisIP.pm'	 => 'docs/WhoisIP.html',
			'lib/Mail/SpamCannibal/Session.pm'	 => 'docs/Session.html',
			'lib/Mail/SpamCannibal/PidUtil.pm'	 => 'docs/PidUtil.html',
			'lib/Mail/SpamCannibal/LaBreaDaemon.pm'	 => 'docs/LaBreaDaemon.html',
			'lib/Mail/SpamCannibal/IP2ccFlag.pm'	 => 'docs/IP2ccFlag.html',
		),},
   'HTMLSCRIPTPODS'	=> {	'rc.sc_dbwatch'		=> 'docs/rc.sc_dbwatch.html',
				'rc.sc_lbdaemon.sample'	=> 'docs/rc.sc_lbdaemon.html',
				'DNSBLserver/rc.dnsbls' => 'docs/rc.dnsbls.html',
				'BDBaccess/rc.bdbaccess' => 'docs/rc.bdbaccess.html',
		  },
   'clean'	  => { FILES	=> "*~ tmp* docs* script/sc_sesswrap"},
   'dist'         => { COMPRESS	=> 'gzip', SUFFIX => 'gz'},
);

# if html conversion has been removed in this perl version then work around here
#
require './fixup/perl2html.pl';
my $workaround = pf_html_check(\%makeparms);

sub MY::post_constants {
  my $post_constants = q|
|. $configtxt .q|
SPAMUID= |. $uid .q|
SPAMGID= |. $gid .q|

MY_POD2TEXT = |. $Config{scriptdirexp} .'/pod2text' .q|
|;
  if ($workaround) {
    $post_constants .= pf_handy_list(\%makeparms);
  }
  $post_constants;
}

sub MY::postamble {
  my $postamble;
  $postamble = q|
.PHONY = install_daemon install_spamcannibal clean_CTest pods/INSTALL.pod install_sc_permissions

INSTALL : pods/INSTALL.pod
	@$(MY_POD2TEXT) pods/INSTALL.pod > INSTALL

pods/INSTALL.pod :
	@$(NOOP)

SiteConfig.pm : config.db
	$(PERL) inst/make_Config.pl

install_spamcannibal	: scripts/sc_sesswrap
	@$(MKPATH) $(SPMCNBL_CONFIG_DIR)
	@$(MKPATH) $(SPMCNBL_SCRIPT_DIR)
	$(RM_F) $(SPMCNBL_SCRIPT_DIR)/sc_remotewrap
	$(CP) -p rc.sc_lbdaemon.sample $(SPMCNBL_SCRIPT_DIR)
	$(CP) -p rc.sc_dbwatch	$(SPMCNBL_SCRIPT_DIR)
	$(CP) -p scripts/*.pl $(SPMCNBL_SCRIPT_DIR)
	$(CP) -p scripts/sc_sesswrap $(SPMCNBL_SCRIPT_DIR)
	@ln -s $(SPMCNBL_SCRIPT_DIR)/sc_sesswrap $(SPMCNBL_SCRIPT_DIR)/sc_remotewrap
	$(CP) -p config/*.sample $(SPMCNBL_CONFIG_DIR)
	$(CP) -rp public_html $(SPAMCANNIBAL_HOME)
	$(RM_F) $(SPAMCANNIBAL_HOME)/public_html/admin.cgi
	@ln -s $(SPAMCANNIBAL_HOME)/public_html/cannibal.cgi $(SPAMCANNIBAL_HOME)/public_html/admin.cgi
	@$(MKPATH) $(SPAMCANNIBAL_HOME)/sess
	@$(MKPATH) $(SPAMCANNIBAL_HOME)/private
	$(CP) -p private/* $(SPAMCANNIBAL_HOME)/private

install_sc_permissions	:
	chown -R $(SPAMUID) $(SPAMCANNIBAL_HOME)
	chgrp -R $(SPAMGID) $(SPAMCANNIBAL_HOME)
	chmod 0700 $(SPAMCANNIBAL_HOME)/sess
	chmod 0700 $(SPAMCANNIBAL_HOME)/private
	chmod 0600 $(SPAMCANNIBAL_HOME)/private/*
	chmod 0640 $(SPAMCANNIBAL_HOME)/config/*
	chmod 0644 $(SPAMCANNIBAL_HOME)/config/sc_web.conf.sample
	if [ -f $(SPAMCANNIBAL_HOME)/config/sc_web.conf ]; then \
	    chmod 0644 $(SPAMCANNIBAL_HOME)/config/sc_web.conf; \
	fi
	chmod 04755 $(SPMCNBL_SCRIPT_DIR)/sc_sesswrap
	chmod 01700 $(SPMCNBL_SCRIPT_DIR)/sc_session.pl
	chmod 0700 $(SPMCNBL_SCRIPT_DIR)/sc_remote.pl
	if [ -d $(SPAMCANNIBAL_HOME)/public_html/tmp ]; then \
	    $(RM_F) $(SPAMCANNIBAL_HOME)/public_html/tmp/*; \
	else \
	    $(MKPATH) $(SPAMCANNIBAL_HOME)/public_html/tmp; \
	    chown -R $(SPAMUID) $(SPAMCANNIBAL_HOME)/public_html/tmp; \
	    chgrp -R $(SPAMGID) $(SPAMCANNIBAL_HOME)/public_html/tmp; \
	    chmod 0777 $(SPAMCANNIBAL_HOME)/public_html/tmp; \
	fi
	if [ -d $(SPAMCANNIBAL_HOME)/public_html/flags ]; then \
	    echo "$(SPAMCANNIBAL_HOME)/public_html/flags exists, skipping..."; \
	else \
	    $(MKPATH) $(SPAMCANNIBAL_HOME)/public_html/flags; \
	    chown -R $(SPAMUID) $(SPAMCANNIBAL_HOME)/public_html/flags; \
	    chgrp -R $(SPAMGID) $(SPAMCANNIBAL_HOME)/public_html/flags; \
	    chmod 0777 $(SPAMCANNIBAL_HOME)/public_html/flags; \
	fi

install_daemon	:
	@cd BDBaccess && $(MAKE) install_daemon $(PASTHRU)
	@cd DNSBLserver && $(MAKE) install_daemon $(PASTHRU)

clean_CTest	:
	@cd BDBaccess && $(MAKE) clean_CTest $(PASTHRU)
	@cd DNSBLserver && $(MAKE) clean_CTest $(PASTHRU)

|;
  if ($workaround) {
    $postamble .= pf_htmlifypods(\%makeparms,\%Config);
  }
  $postamble;
}

sub MY::top_targets {
  my $inherited;
  {
    package MY;   # add dependencies for .pm and xs files
    $inherited = shift->SUPER::top_targets(@_);
  }
  $inherited =~ s|(\npure_all\s+::.+)config(.+)|${1}SiteConfig.pm scripts/sc_sesswrap INSTALL config$2|;
  if ($workaround) {
    $inherited =~ s/(manifypods)/pf_htmlifypods $1/g;
  }
  $inherited .= q|

scripts/sc_sesswrap	: cdata/sc_sesswrap.c
	@$(CC) cdata/sc_sesswrap.c -o scripts/sc_sesswrap

|;
}

sub MY::makefile {
  package MY;
  my $inherited = shift->SUPER::makefile(@_);
  $inherited =~ s/(Makefile\s+:.+)/$1 config.db/;
  $inherited .= q|
config.db :
	@$(NOOP);

|;
}

sub MY::install {
  my $inherited;
  {
    package MY;
    $inherited = shift->SUPER::install(@_);
  }
  $inherited =~ s/(\ninstall\s+::)(.+doc.+install)/$1 install_daemon install_spamcannibal${2} install_sc_permissions/;
  $inherited =~ s/(\ninstall_perl\s+::(.+doc.+install))/$1 install_daemon install_spamcannibal${2} install_sc_permissions/;
  $inherited =~ s/(\ninstall_site\s+::)(.+doc.+install)/$1 install_daemon install_spamcannibal${2} install_sc_permissions/;   
  $inherited =~ s/\s+all\s+/ all clean_CTest /g;
#  $inherited =~ s|(pure_site_install\s+::.*)|$1\n\t\@\$\(MKPATH\) \$\(INSTALLHTMLSITELIBDIR\)|;
  if ($workaround) {
    $inherited = pf_psias($inherited);
  }
  $inherited;
}

sub MY::realclean {
  package MY;   
  my $inherited = shift->SUPER::realclean(@_) . q|
	$(RM_F) config.db
	$(RM_F) SiteConfig.pm
	$(RM_F) scripts/sc_sesswrap
	$(RM_F) INSTALL
|;
}

WriteMakefile(%makeparms);

