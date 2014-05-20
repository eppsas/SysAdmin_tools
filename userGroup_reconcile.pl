#! /usr/bin/perl

####################
## this code is yet another version of the "reconcile UIDs and GIDs" for migration from local
## authentication to LDAP/AD integration for AIX environments
## It has been only partially sanitized and made generic - it is still a work in progress


####################
## pragmas
##########
use strict;
use Getopt::Std;

####################
# global variables
##########

our ($opt_i,$opt_u);
getopts('i:u:');
my $uname = $opt_u;
chomp $uname;
my $id = $opt_i;
chomp $id;
my $hostname = `hostname`;
chomp $hostname;

my $local_passwd = '/etc/passwd';
my $ad_users_file = "ad_user_map.txt";
my $map_file = '/tmp/'."$hostname".'mapper.txt';
my $change_log = '/tmp/mapper_change_log.txt';

my (%loc_users_by_username,%ad_users_by_username) = undef;

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

## load the local password file for parsing
open (IN,"<$local_passwd");
my @local_pass = (<IN>);
close (IN);

## load the ad users file for parsing
open (IN,"<$ad_users_file");
my @ad_users = (<IN>);
close (IN);

my ($old_id,$new_id) = undef;

## parse the local password file for the username and uid
foreach my $line(@local_pass) {
        chomp $line;
        if ($line !~ /\w/) {
                next;
        }
        my ($user,$trash,$uid,$pgid,$trash,$home,$shell) = split /\:/, $line;
        if (!exists $default_user_list{$user}) {
                $loc_users_by_username{$user} = $uid;
                if (($uid == $id) || ($user =~ /$uname/)) {
                        print "FOUND IT => $user\t$uid\t$pgid\t$shell\n";
                        $old_id = $uid;
                }
                #else { 
                #       print "$user\t$uid\t$pgid\t$shell\n";
                #}
        }
}

## parse the ad user file for the username and uid
foreach my $line(@ad_users) {
        chomp $line;
        if ($line !~ /\w/) {
                next;
        }
        my ($username,$realname,$uid) = split /\:/, $line;
        if (($uid == $id) || ($username =~ /$uname/)) {
                print "Found It -> $username\t$uid\n";
                $new_id = $uid;
        }
        #else {
        #       print "$username\t$uid\n";
        #}
}

print "$uname: old=$old_id\tnew=$new_id\n";


my $sdate = `date`;
open (OUT,">>$change_log");
print OUT "$sdate";

## open the mapper file and find all files owned by the target user
open (IN,"<$map_file");
my @mapper = (<IN>);
foreach my $line(@mapper) {
        chomp $line;
        if ($line =~ /^$old_id/) {
                #print "$line\n";
                my ($oldid,$oldgrp,$file) = split /\t/, $line;
                my $cmd = "chown $new_id $file";
                print OUT "$cmd\n";
                my $result = system("$cmd");
                print OUT "result\n";
        }
}

my $edate = `date`;
print OUT "$edate\n\n";
close (OUT);

####################
# subroutines
##########

















