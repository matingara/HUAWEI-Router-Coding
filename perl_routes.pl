#!/usr/bin/perl -w
use strict;
use lib qw("/System/Library/Perl/5.30");

use Net::SSH::Perl;

my $hostname = "hostname";
my $username = "username";
my $password = "password";

my $cmd = shift;

my $ssh = Net::SSH::Perl->new("$hostname", debug=>0);
$ssh->login("$username","$password");
my ($stdout,$stderr,$exit) = $ssh->cmd("$cmd");
print $stdout;