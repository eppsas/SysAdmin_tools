#! /usr/bin/perl

####################
## this code is yet another version of the "reconcile UIDs and GIDs" for migration from local
## authentication to LDAP/AD integration for AIX environments
## It has been only partially sanitized and made generic - it is still a work in progress



####################
## pragmas
##########
use Cwd;
use strict;
#use warnings;

####################
# global variables
##########
my (@group_names,@group_GIDs,@users,@hosts) = undef;
my (%groups_per_host,%hosts_per_group,%groups_by_GID,%users_by_group,%u_groups,%u_users) = undef;
my $target = undef;
## list of groups to be excluded from the reporting later
my %default_group_list = (
	'adm' => 1,
	'audit' => 1,
	'bin' => 1,
	'cron' => 1,
	'kmem' => 1,
	'log' => 1,
	'lp' => 1,
	'mail' => 1,
	'network' => 1,
	'nobody' => 1,
	'power' => 1,
	'printq' => 1,
	'root' => 1,
	'security' => 1,
	'shutdown' => 1,
	'staff' => 1,
	'sys' => 1,
	'system' => 1,
	'tty' => 1,
	'uucp' => 1,
	'users' => 1);
## list of users to be excluded from the reporting later
my %default_user_list = (
	'adm' => 1,
	'bin' => 1,
	'daemon' => 1,
	'esaadmin' => 1,
	'guest' => 1,
	'imnadm' => 1,
	'invscout' => 1,
	'ipsec' => 1,
	'lp' => 1,
	'lpd' => 1,
	'nobody' => 1,
	'nuucp' => 1,
	'root' => 1,
	'snapp' => 1,
	'sshd' => 1,
	'sys' => 1,
	'system' => 1,
	'uucp' => 1);
	

####################
# main program
##########

## open the directory and pull in the list of files
my $dir = cwd();
opendir (DIR,"$dir");
my @dir_contents = readdir(DIR);
closedir (DIR);
my $base_dir = `pwd`;
chomp $base_dir;

## pass the filenames that aren't ".", "..", or the perl script itself to the loader subroutine
foreach my $filename(@dir_contents) {
	chomp $filename;
	#if (($filename !~ /\w/) || ($filename =~ /\.pl$/)) {
	unless ($filename =~ /^p/) {
		next;
	}
	else {
		$target = "$base_dir".'/'."$filename";
		&loader($target);
	}
}

## output section of the main program
@hosts = sort(keys(%groups_per_host));
print "####################\n";
print "# Hosts and groups on the host:\n";
foreach my $line(@hosts) {
	if ($line !~ /\w/) {
		next;
	}
	print "$line\n";
	my @groups = @{$groups_per_host{$line}};
	print join ' ', sort @groups;
	print "\n\n";
}

@group_names = sort(keys(%users_by_group));
print "####################\n";
print "# Groups and users per group:\n";
foreach my $line(@group_names) {
	my %uniques = undef;
	if ($line !~ /\w/) {
		next;
	}
	print "$line\n";
	my @users = @{$users_by_group{$line}};
	foreach my $user(@users) {
		if ($user =~ /\w/) {
			$uniques{$user} = 1;
		}
	}
	@users = sort(keys(%uniques));
	print join ' ', sort @users;
	print "\n\n";
}

@group_GIDs = sort(keys(%groups_by_GID));
print "####################\n";
print "# GIDs and groups per GID:\n";
foreach my $line(@group_GIDs) {
	my %uniques = undef;
	if ($line !~ /\w/) {
		next;
	}
	print "$line\n";
	my @groups = @{$groups_by_GID{$line}};
	foreach my $group(@groups) {
		if ($group =~ /\w/) {
			$uniques{$group} = 1;
		}
	}
	@groups = sort(keys(%uniques));
	print join ' ', sort @groups;
	print "\n\n";
}


my @u_group_list = sort(keys(%u_groups));
my $group_count = 0;
print "####################\n";
print "# Unique groups:\n";
foreach my $line(@u_group_list) {
	chomp $line;
	if ($line !~ /\w/) {
		next;
	}
	unless (exists $default_group_list{$line}) {
		print "$line\n";
		$group_count++;
	}
}
print "Total number of groups: $group_count\n";

print "####################\n";
print "# Hosts per group:\n";
foreach my $line(@u_group_list) {
	chomp $line;
	if ($line !~ /\w/) {
		next;
	}
	unless (exists $default_group_list{$line}) {
		my @lhosts = @{$hosts_per_group{$line}};
		print "$line: @lhosts\n";
	}
}


my @u_user_list = sort(keys(%u_users));
print "####################\n";
print "# Unique users:\n";
foreach my $uuser(@u_user_list) {
	unless (exists $default_user_list{$uuser}) {
		print "$uuser\n";
	}
}


####################
# subroutines
##########

sub loader {
	my $inbound = shift;
	chomp $inbound;
	open (IN,"<$inbound") or warn "can't open $inbound: $!\n";
	my @temp_in = (<IN>);
	close (IN);

	my ($groupname,$group_name,$host) = undef;
	my $filename = reverse($inbound);
	my ($file,$junk) = split /\//, $filename;
	$file = reverse($file);
	my ($host,$junk) = split /\./, $file;
	#print "host -> $host\n";
	

	foreach my $line(@temp_in) {
		chomp $line;
		if ($line !~ /\w/) {
			next;
		}
		if ($line =~ /\!/ )	{
			#print $line;
			my $user = undef;
			my @user_list = undef;
			my ($groupname,$trash,$gid,$users) = split /\:/, $line;
			$u_groups{$groupname} = 1;
			#print "$host -> $groupname\n";
			unless (exists $default_group_list{$groupname}) {
				push (@{$groups_per_host{$host}},"$groupname,");
				push (@{$groups_by_GID{$gid}},"$groupname,");
				push (@{$hosts_per_group{$groupname}},"$host,");
			}
			my @temp = split /\,/, $users;
			foreach my $usr(@temp) {
				if ($usr =~ /\w/) {
					$usr =~ s/\s+//g;
					$u_users{$usr} = 1;
					unless (exists $default_user_list{$usr}) {
						push (@{$users_by_group{$groupname}},"$usr,");
					}
				}
			}
		}
	}
}


######################################################
## Copywrite 2014 Alan S Epps
## 
##  This program is free software: you can redistribute it and/or modify
##     it under the terms of the GNU General Public License as published by
##     the Free Software Foundation, either version 3 of the License, or
##     (at your option) any later version.
## 
##     This program is distributed in the hope that it will be useful,
##     but WITHOUT ANY WARRANTY; without even the implied warranty of
##     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##     GNU General Public License for more details.
## 
##     You should have received a copy of the GNU General Public License
##     along with this program.  If not, see <http://www.gnu.org/licenses/>.
######################################################







