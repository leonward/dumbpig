#!/usr/bin/perl

# Copyright (C) 2009 Leon Ward

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# Contact: leon.ward@sourcefire.com
# 
# TODO  - Require msg
# 	- Add resp keyword
#	- Check for normalized data in content buffers where available (uri modifiers and uricontent)

use strict;
use warnings;

use Parse::Snort;
use Data::Dumper;
use LWP::Simple;

# Nothing to configure - Check out usage()
# ----------------------------------------------
my $rulefile=0;
my $blacklist=0;
my $verbose=0;
my $level=3;
my $version=0.9;
my $censor=0;
my $pause=0;
my $write=0;
my $comment=0;
my $forcefail=0;
my $q=0;
my $fixnormbug=1; 	# I found a bug in Parse::Snort with whitespace normalization, 
			# this is a quick fix while waiting for patch upstream
		

sub getLatestVersion {
	# Check for latest version of dumbpig
	(my $latestVer ,my $url)=(split / /,(get("http://rm-rf.co.uk/downloads/dumbpiglatest.txt")));
	if ($version < $latestVer) {
		print "* NEW VERSION AVAILABLE - $latestVer\n";
		print "* Download here -> $url\n";
		exit 1;
	} else {
		print "No update found\n";
		exit 0;
	}	
}


sub convert_bl{
	# Convert a load of snort rule header format IPs (or CIDR) to the format used by the blacklist patch
	# Note that the BL pacth isn't stable yet, and formats my change etc etc . Use at your own risk
	my $ips = shift;
	my $iplist;

	# 1) Get rid of any [] and , that may have been part of an array of CIDRs earlier
	$ips =~ s/[\[\]]//g;

	# 2) Lets convert this var into a space separated list of CIDR blocks for blacklist
	my @iparray = split(/,/,$ips);
	foreach (@iparray){ 
		# 3) Add a /32 to each bare IP for blacklist
		unless ( "$_" =~ m/.*\/[0-9]/) { 
			$iplist=$iplist . "$_/32 ";
		} else { 	# We must alreasy have a cIDR then, dont add a /32
			$iplist=$iplist . "$_ ";
		}
	}
	return("$iplist");
}

sub chk_ip{
	# Check if we are processing a VAR, IP, or an ANY
	my $ip=shift;

	if ( "$ip" eq "any") {
		return("any");
	} elsif ( "$ip" =~ m/^\$|^\!\$|^\[\$|\!\[\$/) {
		return("var");	
	} elsif ( "$ip" =~ m/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/) {
		return("ip");
	} else {
		# No idea what this is then. FAIL
		return(0);
	}
}

sub chk_pt{
	my $port=shift;

	if ( "$port" eq "any") {
		return("any");
	} elsif ( "$port" =~ m/^\$|^\!\$/) {
		return("var");	
	} elsif ( "$port" =~ m/\b\d{1,5}/) {
		return("num");
	} else {
		# No idea what this is then. FAIL
		return(0);
	}
}

sub usage{
	my $err=shift;

	print "Error : $err\n";
	print "Usage dumbPig <args> \n";
	print "		-u or --update		Check for updates\n";
	print "		-r or --rulefile  	<rulefile>\n";
	print "		-s or --sensitivity 	<1-4> Sensitivity level, Higher the number, the higher the pass-grade\n";
	print "		-b or --blacklist 	Enable blacklist output (see Marty's Blog post for details)\n";
	print "		-p or --pause		Pause for ENTER after each FAIL\n";
	print "		-w or --write		Filename to wite CLEAN rules to\n";
	print "		-q or --quiet		Suppress FAIL, only provide summary\n";
	print "		-d or --disabled	Check rules that are disabled i.e commented out #alert # alert etc\n";
	print "		-v or --verbose		Verbose output for debugging\n";
	print "		-c or --censor		Censor rules in the output, in case you dont trust everyone\n";
	print "		-f or --forcefail	Force good rules to FAIL. Allows output of all rules\n";
	exit 1;
}

my $argcount=1;
foreach (@ARGV) {
        if (("$_" eq "-b") || ("$_" eq "--blacklist")) {
		$blacklist=$ARGV[$argcount];
	} elsif (( "$_" eq "-s" ) || ("$_" eq "--sensivity")) {
		$level=$ARGV[$argcount];
	} elsif (( "$_" eq "-r" ) || ("$_" eq "--rulefile")) {
		$rulefile=$ARGV[$argcount];
	} elsif (( "$_" eq "-w" ) || ("$_" eq "--write")) {
		$write=$ARGV[$argcount];
	} elsif (( "$_" eq "-p" ) || ("$_" eq "--pause")) {
		$pause=1;
	} elsif (( "$_" eq "-v" ) || ("$_" eq "--verbose")) {
		$verbose=1;
	} elsif (( "$_" eq "-d" ) || ("$_" eq "--disabled")) {
		$comment=1;
	} elsif (( "$_" eq "-f" ) || ("$_" eq "--forcefail")) {
		$forcefail=1;
	} elsif (( "$_" eq "-c" ) || ("$_" eq "--censor")) {
		$censor=1;
	} elsif (( "$_" eq "-q" ) || ("$_" eq "--quite")) {
		$q=1;
	} elsif (( "$_" eq "-u" ) || ("$_" eq "--update")) {
		&getLatestVersion;	
	}
	$argcount++;
}

unless ( $q ) {
	print "\nDumbPig version $version - leon.ward\@sourcefire.com \n";
	print "Because I hate looking for the same dumb problems with snort rule-sets\n\n";

	print "  	  __,,    ( Dumb-pig says     )  
	~(  oo ---( \"ur rulz r not so )
	  ''''    ( gud akshuly\" *    )   
	 \n"; # Hey if pulled pork can have a pig, so can I :) -> http://code.google.com/p/pulledpork/ 

	print "Config\n";
	print "----------------------\n";
	print "* Sensivity level - $level/3\n";
	if ($blacklist) {
		print "* Blacklist output : Enabled";
	} else { 
		print "* Blacklist outputi : Disabled\n";
	}
	print "* Processing File - $rulefile\n";
	if ($comment) {
		print "* Check commented out rules : Enabled\n";
	} else {
		print "* Check commented out rules : Disabled\n";
	}
	if ($pause) {
		print "* Pause : Enabled\n";
	} else {
		print "* Pause : Disbled\n";
	}

	if ($forcefail) {
		print "* ForceFail : Enabled\n";
	} else {
		print "* ForceFail : Disabled\n";
	}

	if ($censor) {
		print "* Censor : Enabled\n";
	} else {
		print "* Censor : Disabled\n";
	}

	if ($write) {
		print "* Output clean rules to : $write\n";
	}

	print "* Quite mode : Disabled \n"; 		# We won't see this if it's enabled, so why bother checking?
	print "----------------------\n";
}


unless ($rulefile) { usage("Please specify a rules file"); }
open RULEFILE, "$rulefile" or  die "Unable to open $rulefile";
open OUTPUT,">","$write" or die "Unable to open output file $write";

my $linenum=0;
my $rulecount=0;
my $failnum=0;
my $blackCIDR="";
my @blackArray=();

while (my $line=<RULEFILE>) {
	chomp $line;
	my $originalline = $line;
	$linenum++;

	if ($fixnormbug ) {
		# There is a minor bug in the Parse::Snort module with whitespace, while waiting for a fix (reported) lets "fix" it here.

		# Thanks to Tom Dixon for spotting the problem.
		# Thanks to Per Kristian Johnsen for pointing out that I was breaking peoples rules by writing this output to file.

#		$line =~ s/ *$//g;	# Remove end of line whitespace 
		$line =~ s/: *"/:"/g;	# Remove extra space after : eg. msg:  "foo";
		$line =~ s/^\s+(alert|drop|pass|reject|activate|dynamic|activate)/$1/g; # Remove ws before action keyword e.g. ^     alert ip any	
		$line =~ s/\s+/ /g;	# Normalize All whitespace <- This is brutal and breakes the formatted output

	}

	if ($comment) {
		# User wants to process commented out lines, so lets uncomment them
		$line =~ s/^#alert/alert/g;
		$line =~ s/^# alert/alert/g;
		$line =~ s/^#drop/drop/g;
		$line =~ s/^# drop/drop/g;
	}

	if ( $line =~ m/^alert|^pass|^drop|^reject|^activate|^dynamic/ ) {
		$rulecount++;
		my $rulehash=Parse::Snort->new($line);
		if ($verbose) {
			print "-V Dumping rule hash from Parse::Snort\n";
			print Dumper $rulehash;
		}
		my $fail=0;		# Problem found with rule
		my $blacklistable=0;	# Can this rule be converted to a blacklist?
		my $sffail=0;		# Problem that will stop rule from importing into Sourcefire Defense Center
		my $fatal=0;		# Fatal problem that will prevent the rule from starting in snort. Syntax error etc.
		my @reason=();		# Array of reasons for fail
		my $sfreason="";
		my $display_head="";
		my $display_body="";	
		my $action=0; 
		my $proto=0;
		my $src_addr=0;
		my $src_port=0;
		my $direction=0;
		my $dst_addr=0;
		my $dst_port=0;
		my $unknown=0;
		my @rulelines=();

		############################################################
		# If any of these are 0 post processing, the keyword is not in use.
		my @censorKeywords=("pcre","content","uricontent","msg");
		my @argless=("http_method", 
				"ftpbounce",
				"file_data",
				"nocase",
				"rawbytes",
				"dce_stub_data",
				"http_header",
				"fast_pattern",
				"http_client_body", 
				"http_stat_code",
				"http_stat_msg",
				"http_cookie");	# Some keywords don't take args, these are argless.


		my %hkeywords =("msg" => 0,
				"content" => 0,
				"gid" => 0,
				"sid" => 0, 
				"ttl" => 0, 
				"uricontent" => 0,
				"pcre" => 0,
				"flow" => 0,
				"nocase" => 0,
				"rev" => 0,
				"reference" => 0,
				"classtype" => 0,
				"flowbits" => 0,
				"threshold" => 0,
				"offset" => 0,
				"distance" => 0,
				"within" => 0,
				"offset" => 0,
				"depth" => 0,
				"dsize" => 0,
				"byte_test" => 0,
				"byte_jump" => 0,
				"rawbytes" => 0,
				"isdataat" => 0,
				"ipopts" => 0,
				"tag" => 0,
				"itype" => 0,
				"icode" => 0,
				"flags" => 0,
				"urilen" => 0,
				"fragbits" => 0,
				"fragoffset" => 0,
				"seq" => 0,
				"ack" => 0,
				"window" => 0,
				"id" => 0,
				"ip_proto" => 0,
				"metadata" => 0,
				"priority" => 0,
				"fwsam" => 0,
				"asn1" => 0,
				"http_client_body" => 0,
				"http_cookie" => 0,
				"dce_stub_data" => 0,
				"dce_iface" => 0,
				"dce_opnum" => 0,
				"http_header" => 0,
				"icmp_id" => 0,
				"icmp_seq" => 0,
				"fast_pattern" => 0,
				"http_method" => 0,
				"ftpbounce" => 0,
				"http_header" => 0,
				"http_stat_code" => 0,
				"http_stat_msg" => 0,
				"detection_filter" => 0,
				"file_data" => 0
				);

		if ($verbose) {
			print "----Got Rule $linenum--------------------\n";
		}

		############################################################
		# Check Rule Header

		# Check action
		unless ("$rulehash->{'action'}" =~ m/alert|drop|pass/) {
			print "Action is -$rulehash->{'action'}-\n";
			$fail++;
			$fail++;
			push(@reason, "- Only drop and alert actions are supported on rule imports\n");
		}
		$action=$rulehash->{'action'};

		$display_head=$display_head . "$action ";

		# Check protocol
		if ( $rulehash->{'proto'} =~ m/tcp|udp|icmp|ip/ ) {
			$proto=$rulehash->{'proto'};	
		} else {
			$fail++;
			push(@reason, "- Invalid Protocol $rulehash->{'proto'}\n");
		}
		$display_head=$display_head . "$rulehash->{'proto'} ";
		
		# Source IP
		if ( chk_ip("$rulehash->{'src'}") ) {
			$src_addr=chk_ip("$rulehash->{'src'}");
		} else {
			$fail++;
			push(@reason,"- Invalid src_addr $rulehash->{'src'}\n");
		}

		if ($censor) {
			if ( "$src_addr" eq "ip") {
				$rulehash->{'src'} = "CENSORRD_IP";
			}
		}
		$display_head=$display_head . "$rulehash->{'src'} ";

		# Source Port
		if ( chk_pt("$rulehash->{'src_port'}") ) {
			$src_port=chk_pt("$rulehash->{'src_port'}");
		} else {
			$fail++;
			push(@reason, "- Invalid src_port $rulehash->{'src_port'}\n");
		}
		$display_head=$display_head . "$rulehash->{'src_port'} ";

		# Direction
		if (("$rulehash->{'direction'}" eq "->") or ("$rulehash->{'direction'}" eq "<>")) {
			$direction=1;
		} else {
			$fail++;
			push(@reason, "- Invalid direction $rulehash->{'direction'}\n");
		}
		$display_head=$display_head . "$rulehash->{'direction'} ";

		# Dest IP
		if ( chk_ip("$rulehash->{'dst'}") ) {
			$dst_addr=chk_ip("$rulehash->{'dst'}");
		} else {
			$fail++;
			push(@reason,"- Invalid dst_addr $rulehash->{'dst'}\n");
		}
		if ($censor) {
			if ( "$dst_addr" eq "ip") {
				$rulehash->{'dst'} = "CENSORRD_IP";
			}
		}
		$display_head=$display_head . "$rulehash->{'dst'} ";

		# Dest Port
		if ( chk_pt("$rulehash->{'dst_port'}") ) {
			$dst_port=chk_pt("$rulehash->{'dst_port'}");
		} else {
			$fail++;
			push(@reason, "- Invalid dst_port $rulehash->{'dst_port'}\n");
		}
		$display_head=$display_head . "$rulehash->{'dst_port'} ";


		if ($verbose) {
			print "[v] ---- RULE Head ----\n";
			print "proto $proto \n";
			print "src_addr $src_addr ($rulehash->{'src'})\n";	
			print "src_port $src_port ($rulehash->{'src_port'})\n";	
			print "direction $direction ($rulehash->{'direction'})\n";	
			print "dst_addr $dst_addr ($rulehash->{'dst'})\n";	
			print "dst_port $dst_port ($rulehash->{'dst_port'})\n";	
		}




		if ($verbose) {
			print "[v] ---- RULE Body ----\n";
		}

		############################################################
		# Check Rule Body
		# Process Rule Opts

	 	foreach ($rulehash->{'opts'}) {
			foreach my $keyword (@$_){
				#print "Processing $keyword->[0] \n";
	
				# Check we support this keyword
				if (grep {$_ eq $keyword->[0]} %hkeywords) { 

					unless (grep {$_ eq $keyword->[0]} @argless) {  	# Check if this keyword is argless. If so set to 1 to show it's used
						$hkeywords{$keyword->[0]} = $keyword->[1] ;	# If it takes args, set the value of the keyword in the hash to the arg.
						if ($censor) {
							# Censor the value of some keywords, defined in censor_keywords
							if (grep {$_ eq $keyword->[0]} @censorKeywords) {  	
								push (@rulelines, "$keyword->[0]: \"XXXXXXXX\";");
							} else {
								push (@rulelines, "$keyword->[0]:$keyword->[1];");
							}
						} else {
							push (@rulelines, "$keyword->[0]:$keyword->[1];");
						}
					} else {
						$hkeywords{$keyword->[0]} = 1;
						push (@rulelines, "$keyword->[0];");
					}	
				} else {
					print "WARNING: $keyword->[0] not supported  on line $linenum of $rulefile\n";
					$fail++;
					push (@reason, "- Invalid keyword $keyword->[0] found. \n  Does this tool support the keyword \"$keyword->[0]\" If it should contact me. \n  Have you correctly escaped things that should be escaped?\n  Are you using invalid content chars such as \?\"\& etc that should be represented by their hex values eg content\: \"\|VAL\|\"\;\n");

				}
			}	

		}	
		if ($verbose) {
			print "[v] ------------------\n";
			print "$display_head (\n";
			print "$display_body )\n";
		}


		#print "END New rule lines\n";

		############################################################
		# Rule sanity checking. Has the writer created a valid
		# rule, but forgotten some important performance
		# tweaks, or supporting data

		if ($forcefail) {
			# Force a fail on each rule. Use this for printing the rule source, good for use with -c
			$fail++;
		}

		# Low sensivity = BAD problems
		if ($level >= 1) {   

			# IP rule with a port num (WTF?)
			if ( "$proto" eq "ip" and (("$src_port" ne "any") or ("$dst_port" ne "any"))) {
				$fail++;
				push(@reason, "- IP rule with port number (or var that could be set to a port number). This is BAD and invalid syntax. \n  It is likely that this rule head is not functioning as you expect it to.  \n  The IP protocol doesn't have port numbers. \n  If you want to inspect both UDP and TCP traffic on specific ports use two rules, its faster and valid syntax.\n");
			} 

			# No revision number
			#if ( !$rev ) {
			#	$fail++;
			#	push(@reason, "- No revision number! Please add a rev: keyword\n");
			#}


			unless ( $hkeywords{'rev'} ) {
				$fail++;
				push(@reason, "- No revision number! Please add a rev: keyword\n");

			}

			# No SID 
			unless ( $hkeywords{'sid'}) {
				$fail++;
				push (@reason, "- No SID number! Please add a sid: keyword\n");
			}

			# No classtype 
			unless ( $hkeywords{'classtype'}) {
				$fail++;
				push (@reason, "- No classification specified - Please add a classtype to add correct priority rating\n");
			}

			# unknown keyword
			if ( $unknown ) {
				$fail++;
				push (@reason, "- Unknown keyword \"$unknown\" found! Either \n A) you messed up\n B) This tool doesnt support that keyword - contact leon.ward\@sourcefire.com \n C) You are using reserved chars in your rule, HEX should be used for stuff like \" ?() etc \n Note that the decoded rule will NOT show this keyword, check the original rule line\n");
			}
		}

		# Medium sensivity level = Medium problems
		if ($level > 2 ) { 
			# IP rule with flow - move to TCP/UDP
			if ( ("$proto" eq "ip") and $hkeywords{'flow'} ) {
				$fail++;
				push (@reason, "- IP rule with flow?, Considder moving to a TCP or UDP (with stream5) based rule\n");
			}

			# No deep packet checks - Firewall suited check
			if  ( ("$proto" eq "tcp" or "$proto" eq "udp") and not 
				($hkeywords{'content'} or $hkeywords{'uricontent'} or $hkeywords{'pcre'} or $hkeywords{'byte_test'} or $hkeywords{'dsize'} or $hkeywords{'flags'}) ) {
				$fail++;
				$blacklistable=1;
				push (@reason, "- TCP/UDP rule with no deep packet checks? This rule looks more suited to a firewall or blacklist\n"); 
			}

			# IP rule without content, pcre or uricontent?
			if ( "$proto" eq "ip" and not ($hkeywords{'content'} or $hkeywords{'uricontent'} or $hkeywords{'pcre'} or $hkeywords{'ip_proto'})) {
				$blacklistable=1;
				$fail++;
				push (@reason, "- IP rule without a content match. Put this in a firewall!\n");
			}

			# PCRE w/o fast ptn match
			if ( $hkeywords{'pcre'} and not ($hkeywords{'content'} or $hkeywords{'uricontent'}))  {
				$fail++;
				push (@reason, "- PCRE found without a fast-pattern match keyword (content || uricontent). Obvious performance hit here\n");
			}

		}

		# High sensitivity = Minor problems
		if ($level >=3) {
			# TCP without flow
			if ( ("$proto" eq "tcp") and not $hkeywords{'flow'}) {
				$fail++;
				push (@reason, "- TCP, without flow. Considder adding flow to provide better state tracking on this TCP based rule\n");
			}
		}


		if ($level >=4) {
			# Any any any any rule..... SLOW
			if (("$src_addr" eq "any") and ("$dst_addr" eq "any") and ("$src_port" eq "any") and ("$dst_port" eq "any")) {
				$fail++;
				push (@reason, "- ANY ANY -> ANY ANY rule. Come on, surely you can do better than that!? \n  If you are importing into a Sourcefire DC, look at metadata service \n");
			}
		}	

		# If this is a blacklist-able rule, and blacklist o/p is enabled, lets track these for use in a snort.conf
		if ( $blacklist and $blacklistable ) {
			# Chck we have some real IP's and dont end up adding $HOME_NET :)
			# This isn't the smartest way to do this, but works in my tests - Leon

			if ( "$src_addr" eq "ip" ) { 	# We have an IP/CIDR for src_addr here then
				my $blackTarget=convert_bl("$rulehash->{'src'}") . "	# From Sid $hkeywords{'sid'} : $hkeywords{'msg'} : $rulefile";
				push(@blackArray,$blackTarget);
				if ($verbose) {
					print "V- Adding Source $blackTarget to blacklist\n";
				}
			}
			if ( "$dst_addr" eq "ip" ) { 	# We have an IP/CIDR for src_addr here then
				my $blackTarget=convert_bl("$rulehash->{'dst'}");
				push(@blackArray, $blackTarget);
				if ($verbose) {
					print "V- Adding Destination $blackTarget to blacklist\n";
				}
			}
		}

		if ($fail) {
			$failnum++;
			# We have a problem with this rule.
			unless ($q) {
				print "Issue $failnum \n";
				print "$fail Problem(s) found with rule on line $linenum of $rulefile\n";
				print "\n$display_head ( \\ \n";
				foreach (@rulelines) {
					print "\t$_ \\ \n";
				}
				print ")\n";

				foreach (@reason) {
					print "$_";
				}
				unless ($censor ) {
					print "\nRule source sid: $hkeywords{'sid'} \n";
					print "$originalline\n";
				}
				print "=============================================================================\n";
				if ($pause) {
					print "Press Enter for the next fail \n";
				print "=============================================================================\n";
					my $foobar=<STDIN>;
				}
			}
		} else { # WIN!
			print OUTPUT "$originalline\n";	
		}
	} 
}

if ($write) {
	close(OUTPUT);
}

if ($blacklist) {
	print "============================================\n";
	print " Creating blacklist $blacklist\n";
	open BLACKLIST,">","$blacklist" or die "Unable to open blacklist file $blacklist";
	print BLACKLIST "# Autogenerated blacklist by DumbPig from $rulefile \n# Contact leon.ward\@sourcefire.com \n# For more information about dumbPig visit http://rm-rf.co.uk\n ";
	foreach (@blackArray) {
		print BLACKLIST "$_ \n";
	}	
	print "....Done\n";
}

print "--------------------------------------\n";
print "Total: $failnum fails over $rulecount rules ($linenum lines) in $rulefile\n";
print "- Contact leon.ward\@sourcefire.com\n";
