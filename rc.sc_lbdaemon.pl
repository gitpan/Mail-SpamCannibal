#!/usr/bin/perl
#
# sc_lbdaemon.pl
# version 1.01, 9-10-03
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
use Mail::SpamCannibal::LaBreaDaemon qw(daemon);

#################### SET THESE FOR YOUR SITE ############
my $config = {

# path to the tarpit daemon
#
  'LaBrea'	=> '/usr/local/spamcannibal/bin/dbtarpit',

# the port to listen on. REQUIRED 
#
  'd_port'	=> 8687,

# the default interface for listen socket. REQUIRED
#
  'd_host'	=> 'localhost',

# what hosts are allowed to connect, defaults to ALL
#
  'allowed'	=> 'localhost',

# directory and path for pid file -- recommend dbtarpit environment directory
#
  'pid'		=> '/var/run/dbtarpit/sc_lbdaemon.pid',

# directory and path for dameon cache -- recommend dbtarpit environment
#
  'cache'	=> '/var/run/dbtarpit/sc_lbdaemon.cache',

# location/name of dbtarpit fifo
#
  'fifo'	=> '/var/run/dbtarpit/dbtplog',

# maximum concurrent children, recommend 2 on slow hosts, default 5
#  'kids'	=> 5,

# cache file mask, default 033
#  'umask'	=> 033,

# time between forced culls of old threads in memory, default 600
#  'cull'	=> 600,

# number of recent threads to track
#
  'scanners'	=> 100,
};  

##################### END CONFIG #########################

daemon($config);
