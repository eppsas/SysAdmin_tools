#! /usr/bin/perl

use File::Find;
use strict;

my $hostname = `hostname`;
chomp $hostname;
print "$hostname\n";
my $start_time = localtime;
print "$start_time\n";

my $basedir = '/';
my $mapper_file = '/tmp/'."$hostname".'mapper.txt';
open (OUT,">$mapper_file");

find(\&print_name_if_dir, "$basedir");

close (OUT);
my $end_time = localtime;
print "$end_time\n";

sub print_name_if_dir {
	my $file = $_;
	my ($dev, $ino, $mode, $nlink, $uid, $gid) = lstat($file);
	my $cur_dir = $File::Find::dir;
	print OUT "$uid\t$gid\t$cur_dir/$file\n";
}

