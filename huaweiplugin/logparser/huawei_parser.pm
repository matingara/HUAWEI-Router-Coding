#!/usr/bin/perl

# Parse logs from huawei device
#
# $Id: huawei_parser.pm,v 1.0 2017/06/01 12:00:00 zsf Exp $
#

use strict;
use warnings;

package huawei_parser;


############################################################################
# This parser parses the following message types:
# 
# --------------------------------------------------------------------------
# Traffic log:
# Mar 29 2017 16:23:39 USG6600 %%01POLICY/6/POLICYPERMIT(l):vsys=abc, protocol=17, source-ip=63.1.1.8, source-port=137, destination-ip=63.1.1.255, destination-port=137, time=2017/3/30 01:23:39, source-zone=untrust, destination-zone=untrust, rule-name=eeeee.
#
# --------------------------------------------------------------------------
# Audit log:
# Mar 29 2017 16:06:54 USG6600 %%01SHELL/5/CMDRECORD(s)[97]:Recorded command information. (Task=HTPR, Ip=4.1.93.42, VpnName=, User=admin, AuthenticationMethod="Null", Command="action deny")
#
# --------------------------------------------------------------------------
# Audit log(new):
# May 22 2017 03:17:19 USG6000V2 CONFIG/4/CONFIGCHANGE:OID 1.3.6.1.4.1.2011.6.122.83.1.2.1 The configuration has been changed.( UserName=root, TerminalIp=4.1.88.77, VsysName=aa, ModuleType=Security-Policy,  ModuleObject=abc, Action=ADD, TargetObject=)  
#
# "The user entered a command that modified the configuration."
############################################################################

my $PARSER_EXCLUDE_FILENAME = "huawei_parser_exclude.txt";

my @ignore_regexps = (
);

sub parserId
{
	return "huawei";
}

sub init
{
	# open the parser regexp exclude file
	# and add each line to 
	my $exclude;
	my $line;
	my $parser_name = parserId();
	
	if (!open($exclude, $PARSER_EXCLUDE_FILENAME)){
		#print "$parser_name_parser::init: Error - failed to open file: $PARSER_EXCLUDE_FILENAME\n";
		return 0;
	}
	while($line = <$exclude>){
		chomp($line);
		push (@ignore_regexps, $line);
	}
	close($exclude);
	return 1;
}

sub ignore_quota
{
	my $object_name = shift;
	$object_name =~ s/\"//g;
	return $object_name
}

sub parse
{
	my $message = shift;
	my $logFields = shift;
	my $headerFields = shift;
	my $log_line_time = shift;

	# Traffic log:
	# Mar 29 2017 16:23:39 USG6600 %%01POLICY/6/POLICYPERMIT(l):vsys=abc, protocol=17, source-ip=63.1.1.8, source-port=137, destination-ip=63.1.1.255, destination-port=137, time=2017/3/30 01:23:39, source-zone=untrust, destination-zone=untrust, rule-name=eeeee.
	#
	if ($message =~ /%%01POLICY\/\d\/(POLICYPERMIT|POLICYDENY)\(l\)(.+)/)
	{
		my $action = $1;
		my $log = $2;

		$logFields->{'type'} = 'traffic';
		if ( $log =~ /vsys=(\S+),\s/ ){
			$logFields->{'virtual_system'} = $1;
		}		
		if ( $log =~ /rule-name=(.+)\.$/) {
			$logFields->{'policy_id'} = $1;
		}
		if ( $log =~ /protocol=([^,]*)/ ) {
			$logFields->{'protocol'} = $1;
		}
		if ( $log =~ /source-zone=([^,]*)/ ){
			$logFields->{'src_zone'} = $1;
		}
		if ( $log =~ /source-ip=([^,]*)/ ){
			$logFields->{'src_ip'} = $1;
		}
		if ( $log =~ /source-port=([^,]*)/ ) {
			$logFields->{'src_port'} = $1;
		}
		if ( $log =~ /destination-zone=([^,]*)/ ) {
			$logFields->{'dst_zone'} = $1;
		}
		if ( $log =~ /destination-ip=([^,]*)/ ) {
			$logFields->{'dst_ip'} = $1;
		}
		if ( $log =~ /destination-port=([^,]*)/ ) {
			$logFields->{'dst_port'} = $1;
		}
		if ( $log =~ /time=([^,]*)/ ) {
			if(my ( $year, $mon, $day ) = $1 =~ /^(\d{4})\/(\d{1,2})\/(\d{1,2})\s\d{1,2}:\d{1,2}:\d{1,2}/ ){
				$mon =~ s/^(\d)$/0$mon/;
				$day =~ s/^(\d)$/0$day/;
				$logFields->{'start_date'} = "$year$mon$day";
			}
		}
		if($action eq "POLICYPERMIT"){
			$logFields->{'action'} = "allow";
		}
		else{
			$logFields->{'action'} = "deny";
		}
		$logFields->{'count'} = 1;
		return 1;
	}
	# Audit log(new):
	# May 22 2017 03:17:19 USG6000V2 CONFIG/4/CONFIGCHANGE:OID 1.3.6.1.4.1.2011.6.122.83.1.2.1 The configuration has been changed.( UserName=root, TerminalIp=4.1.88.77, VsysName=aa, ModuleType=Security-Policy,  ModuleObject=abc, Action=ADD, TargetObject=)  
	#
	if($message =~ /CONFIG\/\d\/CONFIGCHANGE:OID (.+)/)
	{
		my $log = $1;
		$logFields->{'type'} = 'audit';
		if ( $log =~ /VsysName=(\S+),\s/ ){
			$logFields->{'virtual_system'} = $1;
		}	
		if ( $log =~ /UserName=([^,]*)/ ) {
			$logFields->{'user'} = $1;
		}
		if ( $log =~ /ModuleType=([^,]*)/ ){
			if($1 eq "Security-Policy"){
				$logFields->{'object_type'} = "rule";
			}
			elsif($1 eq "Address-Set" || $1 eq "Address-Group"){
				$logFields->{'object_type'} = "host";
			}
			elsif($1 eq "Service-Set" || $1 eq "Service-Group"){
				$logFields->{'object_type'} = "service";
			}
			else{
				return 0;
			}
		}
		if ( $log =~ /ModuleObject=([^,]*)/ ){
			$logFields->{'object_name'} = $1;
		}
		if ( $log =~ /Action=([^,]*)/ ) {
			if($1 eq "ADD"){
				$logFields->{'action'} = "create";
			}
			elsif($1 eq "DELETE"){
				$logFields->{'action'} = "delete";
			}
			elsif($1 eq "RENAME"){
				$logFields->{'action'} = "rename";
			}
			else{#elsif($1 eq "MERGE" || $1 eq "MOVE-BEFORE" || $1 eq "MOVE-AFTER")
				$logFields->{'action'} = "modify";
			}
		}

		if(defined $log_line_time && $log_line_time =~ /^(\d{4})\/(\d{2})\/(\d{2})\s(\d{2}):(\d{2}):(\d{2})$/){
			$logFields->{'timeGen'} = $log_line_time;
		}
		else{
			$logFields->{'timeGen'} = $headerFields->{'timestamp'};
		}

		$logFields->{'timestamp'} = $headerFields->{'timestamp'};
		$logFields->{'detail'} = $log;

		return 1;
	}
	# Audit log:
	# May  3 2017 09:03:43 USG6000V1 %%01SHELL/5/CMDRECORD(s)[19]:Recorded command information. (Task=co0, Ip=**, VpnName=, User=admin, AuthenticationMethod="Local-user", Command="rule name test")
	#
	if ($message =~ /%%01SHELL\/\d\/CMDRECORD\(s\).+Command=\"(.+)\"/)
	{
		my $cmd = $1;
		my $log_invalid = 0;
		
		if($cmd =~ /^(undo )?rule name (("[^"]*")|(\S+))$/){
			$logFields->{'object_type'} = "rule";
			$logFields->{'object_name'} = ignore_quota($2);
			if($1){
				$logFields->{'action'} = "delete";
			}
			else{
				$logFields->{'action'} = "modify";
			}
			$log_invalid = 1;
		}
		elsif($cmd =~ /^undo rule name all$/){
			$logFields->{'object_type'} = "rule";
			$logFields->{'object_name'} = "all";
			$logFields->{'action'} = "delete";
			$log_invalid = 1;
		}
		elsif($cmd =~ /^rule rename (("[^"]*")|(\S+)) (("[^"]*")|(\S+))$/ || $cmd =~ /^rule move (("[^"]*")|(\S+)) \S+/){
			$logFields->{'object_type'} = "rule";
			$logFields->{'object_name'} = ignore_quota($1);#use old name
			$logFields->{'action'} = "modify";
			$log_invalid = 1;
		}
		elsif($cmd =~ /^rule copy (("[^"]*")|(\S+)) (("[^"]*")|(\S+))$/){
			$logFields->{'object_type'} = "rule";
			$logFields->{'object_name'} = ignore_quota($4);
			$logFields->{'action'} = "create";
			$log_invalid = 1;
		}
		elsif($cmd =~ /^(undo )?ip address-set (("[^"]*")|(\S+))( type (object|group))?$/){
			$logFields->{'object_type'} = "host";
			$logFields->{'object_name'} = ignore_quota($2);
			if($1)
			{
				$logFields->{'action'} = "delete";
			}
			else
			{
				$logFields->{'action'} = "modify";
			}
			$log_invalid = 1;
		}
		elsif($cmd =~ /^rename ip address-set (("[^"]*")|(\S+)) address-set (("[^"]*")|(\S+))$/){
			$logFields->{'object_type'} = "host";
			$logFields->{'object_name'} = ignore_quota($1);#use old name
			$logFields->{'action'} = "rename";
			$log_invalid = 1;
		}
		elsif($cmd =~ /^(undo )?ip service-set (("[^"]*")|(\S+))( type (object|group))?$/){
			$logFields->{'object_type'} = "service";
			$logFields->{'object_name'} = ignore_quota($2);
			if($1)
			{
				$logFields->{'action'} = "delete";
			}
			else
			{
				$logFields->{'action'} = "modify";
			}
			$log_invalid = 1;
		}
		elsif($cmd =~ /^rename ip service-set (("[^"]*")|(\S+)) service-set (("[^"]*")|(\S+))$/){
			$logFields->{'object_type'} = "service";
			$logFields->{'object_name'} = ignore_quota($1);#use old name
			$logFields->{'action'} = "rename";
			$log_invalid = 1;
		}
		elsif($cmd =~ /^default action (permit|deny)$/ || $cmd =~ /^(undo )?default policy logging$/ || $cmd =~ /^(undo )?default session logging$/){
			$logFields->{'object_type'} = "rule";
			$logFields->{'object_name'} = "default";
			$logFields->{'action'} = "modify";
			$log_invalid = 1;
		}

		if($log_invalid){
			$logFields->{'type'} = 'audit';
			$logFields->{'virtual_system'} = $headerFields->{'hostname'};#TODO, can't tell which system is.
			if($message =~ /User=([^,]*)/){
				$logFields->{'user'} = $1;
			}

			if(defined $log_line_time && $log_line_time =~ /^(\d{4})\/(\d{2})\/(\d{2})\s(\d{2}):(\d{2}):(\d{2})$/){
				$logFields->{'timeGen'} = $log_line_time;
			}
			else{
				$logFields->{'timeGen'} = $headerFields->{'timestamp'};
			}

			$logFields->{'timestamp'} = $headerFields->{'timestamp'};
			$logFields->{'detail'} = $cmd;
			return 1;
		}
	}

	return -1;#ignore this log
}

return 1;
