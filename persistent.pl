#!/usr/bin/perl -w

# THIS SCRIPT IS PROVIDED "AS IS" WITH NO WARRANTIES OR GUARANTEES OF ANY
# KIND, INCLUDING BUT NOT LIMITED TO MERCHANTABILITY AND/OR FITNESS FOR A
# PARTICULAR PURPOSE. ALL RISKS OF DAMAGE REMAINS WITH THE USER, EVEN IF THE
# AUTHOR, SUPPLIER OR DISTRIBUTOR HAS BEEN ADVISED OF THE POSSIBILITY OF ANY
# SUCH DAMAGE. IF YOUR STATE DOES NOT PERMIT THE COMPLETE LIMITATION OF
# LIABILITY, THEN DO NOT DOWNLOAD OR USE THE SCRIPT. NO TECHNICAL SUPPORT
# WILL BE PROVIDED.

# persistent.pl
# Eric Conrad
#
# usage: ./persistent.pl < /var/squid/log/access.log
#
# Reports persistent http connections via the proxy, where a client
# persistently connects to the same site over a long duration of time.
#
# May identify reverse http proxies, and worms/trojans that 'phone home' 
# on a regular basis
# 
# May also identify legitimate persistent connections, such as weather 
# toolbars, streaming media, etc.  Expect false positives.
# 
# Best to scan on 'off-hours' traffic (late night to early morning)
#
# output is client -> server pairs, sorted by number of connections
#
# Assumes squid proxy log format with "emulate_httpd_log" set to "on"
#
# Here's an example of GET and CONNECT entries:
#
# 172.23.102.26 - - [02/Apr/2007:14:25:06 -0400] "GET http://img.mqcdn.com/mapquest/brands/mqsite/promos-min.css?v=1.191 HTTP/1.0" 200 3812 TCP_MISS:DIRECT
# 172.22.116.210 - - [19/May/2007:06:30:02 -0400] "CONNECT telrad.mobilexusa.com:443 HTTP/1.0" 200 1010 TCP_MISS:DIRECT

my $numbertoreport=50;  # Report on the top X persistent connections
my $lastmin=0;          # Used to track unique visits per 5 minute intervals
my $min=0;              # current minute
my $url="";             # URL that is visited
my @urlfields="";       # array to store fields of the URL
my @datefields="";      # array to store fields of the date
my $client="";          # Address of the client
my $date="";            # Date of the connection
my $site="";            # Remote site
my @logline="";         # One line of the log
my $connection="";      # client -> site pair
my %seen;		# hash of current connections
my %persistent;         # hash of persistent connections
my $key="";             # key for sorting hashes

while(<>){                      # Read STDIN
  if ((/ \"CONNECT /)||(m!GET http://\w!i)){
    @logline=split(/\s+/,$_);
    $client=$logline[0];            # Grab the client IP
    $date=$logline[3];          # Grab the date
    if (/ \"CONNECT /){         # CONNECT and GET log in a different format
      $site=$logline[6];        # Grab the remote site
    }
    else{
      $url=$logline[6];         # Grab the URL
      @urlfields=split("\/",$url);
      $site=$urlfields[2];      # Grab the remote site
    }
    $connection="$client $site"; # Create a client -> remote site pair
    $seen{$connection}=1;       # client-> site pair was 'seen' in this 5-minute interval
    @datefields=split(":",$date);
    $min=$datefields[2];        # Grab the current minute
    if ((($min%5)==0) and ($min!=$lastmin)){  # Entering new 5-minute interval
      $lastmin=$min;
      foreach $key (keys %seen) {
        $persistent{$key} += $seen{$key}; # Increase total for client-> site visits
        $seen{$key}=0;                    # resent 'seen' for next 5-minute interval 
      }
    }
  }
}
# Sort the connections, highest to lowest:
@keys = sort {
  $persistent{$b} cmp $persistent{$a}
} keys %persistent;

# Print top X persistent connections:
print "Count Client            Remote Site\n";
print "------------------------------------------\n";
foreach (@keys) {
  ($client,$site)=split(' ');
  #print "$_ $persistent{$_}\n";
  printf ("%3d   %-17s %-40s\n",$persistent{$_},$client,$site);
  $numbertoreport--;
  last if ($numbertoreport<1);
}
