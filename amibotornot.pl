#!/usr/bin/perl
use strict;
use warnings;
use POE qw/Wheel::FollowTail/;
use Apache::LogRegex;
use Data::Dumper;
use Getopt::Long('GetOptions');
use DBI;
use Carp;
use DateTime::Format::HTTP;
use DB_File;
use constant {
	HOST =>'%h',
	VHOST => '%v',
	LOGNAME => '%l',
	REMOTE_USER => '%u',
	TIME => '%t',
	REQUEST => '%r',
	STATUS => '%>s',
	BYTES => '%b',
	HTTP_REFERER => '%{Referer}i',
	USER_AGENT => '%{User-Agent}i'
};

my %o;
GetOptions(
	\%o, 
	'debug=i',
	'help', 	
	'logfile=s', 
	'dbfile=s', 
	'ua_suspicious_re=s',
	'ua_whitelist_re=s',
	'host_whitelist_re=s',
	'request_whitelist_re=s'
	);

if($o{help}){
	print usage();
}

my $dbfile = $o{dbfile} || 'bottracking.db';

my $dbh = DBI->connect("dbi:SQLite:dbname=$dbfile","","",{ RaiseError => 1, AutoCommit => 0 }) or croak($DBI::errstr);
use DateTime::Format::HTTP;
my $dt_class = 'DateTime::Format::HTTP';

init_dbs($dbh);
my $statements = init_statements($dbh);

$|=1;

#These are exactly matched.
my %suspicious_uas = (
	'Mozilla/4.0' => 1,
	'Mozilla/5.0' => 1,
	'Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)' => 1,
	'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)' => 1,
	'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)' => 1,
	'Mozilla/4.0 (compatible;)' => 1,
	'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9)' => 1,
	'Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)' => 1,
	'Mozilla/4.0 (compatible; MSIE 5.0; Windows 98)' => 1,
	'Mozilla/4.0 (compatible; MSIE 6.0; Windows 98)' => 1,
	'Mozilla/5.0 Firefox/3.0.5' => 1,
	'Mozilla/3.0 (compatible)' => 1,
	'Mozilla/2.0 (compatible)' => 1,
	'Mozilla/4.0 (compatible; MSIE 6.0; MSIE 5.5; Windows NT 4.0) Opera 7.0 [en]' => 1,
	'Opera' => 1,
	'-' => 1,
	'0' => 1
);

my $suspicious_ua_re = (exists($o{ua_suspicious_re})) ? qr/$o{ua_suspicious_re}/i : qr/shelob|curl|mechanize/i;
my $useragent_whitelist = (exists($o{ua_whitelist_re})) ? qr/$o{ua_whitelist_re}/i : qr/loc\.gov|googlebot|slurp|msnbot|google\.com\/feedfetch|ask jeeves|ia_archiver|bloglines|feedhub|spinn3r|livejournal/i;
my $host_whitelist = (exists($o{host_whitelist_re})) ? qr/$o{host_whitelist_re}/i : qr/^(128\.103|192\.168|140\.247|98\.217\.158\.47|173\.13\.115\.145|173\.48\.204\.141)/i;
my $request_whitelist = (exists($o{request_whitelist_re})) ? qr/$o{request_whitelist_re}/i : qr/action\/ajax|explore\/module|includes|svn\//i;

# 120.63.7.165 www.citmedialaw.org - [31/Aug/2010:11:26:21 -0400] "GET / HTTP/1.1" 200 252 "-" "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/3.0.195.38 Safari/532.0"


my $lr = Apache::LogRegex->new($o{log_format} || '%h %v %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"');

my $FILENAME = $o{logfile} || '/web/adam/proxy/logs/apache2/access.log';

POE::Session->create(
  inline_states =>
    {
      _start => \&log_handler ,
      got_line => \&process_line ,
      expire_requests => \&expire_requests,
      write_iptables_rules => \&write_iptables_rules,
      block_host => \&block_host
    },
);

sub log_handler{
	$_[HEAP]->{wheel} =
	POE::Wheel::FollowTail->new(
		Filename => $FILENAME,
		InputEvent => 'got_line'
	);
	$_[KERNEL]->alarm( write_iptables_rules => time() + 15 );
	$_[KERNEL]->alarm( expire_requests => time() + 90 );
}

$poe_kernel->run();

sub write_iptables_rules{
	if(defined $o{debug}){
		print "Writing block file . . ." . time() ."\n";
	}

	if(! `iptables -n -L bad_ips 2> /dev/null`){
		#chain doesn't exist. Create it.
		system('/sbin/iptables -N bad_ips');
		system('/sbin/iptables -I INPUT -p tcp -m multiport --dports 80,443 -j bad_ips');
	}

	#Ignore blocks older than some interval greater than the time between when we run this method.
	#Running every 15 seconds, so let's say 30 sec.
	my $platforms_to_block = $dbh->selectall_arrayref($statements->{get_blocks_to_write}, {Columns => {}}, (time - 30));
	
	my @blocked_already = split(/\n/,`/sbin/iptables -n -L bad_ips 2> /dev/null`);

	# -A bad_ips -s 62.215.9.98 -j DROP
	# convert to a hash
	my %blocked_already;
	foreach(@blocked_already){
		my @line = split(' ',$_);
		$blocked_already{$line[3]} = 1;
	}

	foreach my $to_block(@$platforms_to_block){
		my $host = $to_block->{host};

		if(! exists($blocked_already{$host}) ){
	    	my $iptables_command =  "/sbin/iptables -A bad_ips -j DROP -s $host\n";
			my $at_command = "echo \"/sbin/iptables -D bad_ips -j DROP -s $host > /dev/null\" | at now +1 hours\n";

#			print "$iptables_command\n";
#			print "$at_command\n";
			
			system($iptables_command);
			system($at_command);
		}

	}

	#Reschedule for 15 seconds out.
	$_[KERNEL]->alarm( write_iptables_rules => time() + 15 );
}

sub expire_requests{
	if(defined $o{debug}){
		print "Expiring requests and committing. . ." . time() ."\n";
	}
	$statements->{expire_requests}->execute( time - 1200 );
	$_[KERNEL]->alarm( expire_requests => time() + 90);
	$dbh->commit();
}


sub whitelisted{
	my $line = shift;
	if( ($line->{(HOST)} =~ $host_whitelist) || ($line->{(USER_AGENT)} =~ $useragent_whitelist) || ($line->{(REQUEST)} =~ $request_whitelist) ){
		if(exists $o{debug} && $o{debug} > 1){
			print "\nWhitelisted: ".$line->{(HOST)} . " User-Agent: ".$line->{(USER_AGENT)}."\n";
		}
		return 1;
	}
}

sub track_basic_request_parameters_dbi{
	my ($request_id,$line) = @_;
	if($line->{(REQUEST)} =~ / \/robots\.txt/i){
		$statements->{insert_request_attribute}->execute($request_id,'robots');
	}
	if($line->{(REQUEST)} =~ / \/favicon\.ico/i){
		$statements->{insert_request_attribute}->execute($request_id,'favicon');
	}

	if($line->{(REQUEST)} =~ /\.jpe?g|\.css|\.png|\.bmp|\.gif|\.mp3?|\.mov|\.m4v|\.mpg|\.ogg|\.xlsx?|\.docx?|\.pptx?|\.js|\.swf|\.jar|\.ico|\.pdf|\.rss|\.xml/i){
		if(exists $o{debug} && $o{debug} > 1){
			print "\n" . $request_id . " is not for HTML\n";
		}
		$statements->{insert_request_attribute}->execute($request_id,'non_html');
	} 
	else {
		$statements->{insert_request_attribute}->execute($request_id,'html');
	}
	if($line->{(REQUEST)} =~ /feed\/?|atom\/?|rdf\/?$/i){
		if(exists $o{debug} && $o{debug} > 1){
			print "\n".$request_id . " is for a feed\n";
		}
		$statements->{insert_request_attribute}->execute($request_id,'feed');
	}
}

sub block_host{
	my ($line,$reason) = ($_[ARG0], $_[ARG1]);
	$statements->{block_host}->execute($line->{(HOST)}, $line->{(USER_AGENT)},time,$reason);
	if(exists $o{debug}){
		print "Block: ".$line->{(HOST)}. $reason."\n";
	}

#	$_[KERNEL]->alarm( write_iptables_rules => time() - 1);
}

sub calculate_request_ratio{
	# So 1 means only binary content.
	# 0 means only HTML content.
	my ($host,$user_agent) = @_;
	my ($non_html) = $dbh->selectrow_array($statements->{get_platform_request_count_by_attribute},undef,($user_agent,$host,'non_html')); 
	my ($html) = $dbh->selectrow_array($statements->{get_platform_request_count_by_attribute},undef,($user_agent,$host,'html'));
	if($non_html == 0){
		return 0;
	}	
	if($html == 0){
		return 1;
	}
	return ($non_html / ($html + $non_html) );
}

sub apache_to_epoch_time{
	my $time = shift;
	$time =~ s/\[|\]//g;
	my $dt = $dt_class->parse_datetime($time);
	$dt_class->format_datetime($dt);
	return $dt->epoch();
}

sub process_line{
	my %line;
	eval{%line = $lr->parse($_[ARG0])};
	if($@){
          warn 'Unable to parse line: ' . $@;
	}
	else{
		return if whitelisted(\%line);
		my $method = substr($line{(REQUEST)},0,4);
		return unless($method eq 'GET ' || $method eq 'POST' || $method eq 'HEAD');
		
		return unless($line{(STATUS)} == 200 || $line{(STATUS)} == 201 || $line{(STATUS)} == 202 || $line{(STATUS)} == 403 );

		if(exists $o{debug}){
			print '.';
		}
		$statements->{insert_request}->execute($line{(HOST)},$line{(USER_AGENT)},apache_to_epoch_time($line{(TIME)}),$line{(HTTP_REFERER)},$line{(BYTES)},$line{(REQUEST)});
		my $request_id = $dbh->func('last_insert_rowid');

		track_basic_request_parameters_dbi($request_id,\%line);

		my ($requests_from_platform) = $dbh->selectrow_array($statements->{get_platform_request_count}, undef,($line{(USER_AGENT)}, $line{(HOST)}));
		my ($requests_for_url_from_host) = $dbh->selectrow_array($statements->{get_host_url_count}, undef,($line{(HOST)},$line{(REQUEST)}));
		my ($requests_for_url_from_platform) = $dbh->selectrow_array($statements->{get_platform_url_count}, undef,($line{(USER_AGENT)}, $line{(HOST)},$line{(REQUEST)}));

		if(exists($o{debug}) && $o{debug} > 1){
			print "$requests_from_platform requests from ". $line{(HOST)} ." : ". $line{(USER_AGENT)}."\n";
		}

		my $request_ratio = undef;

#		if($requests_from_platform > 5){
			$request_ratio = calculate_request_ratio($line{(HOST)},$line{(USER_AGENT)});
#		}

		if(exists $o{debug} && $o{debug} > 1 && defined($request_ratio) && $requests_from_platform > 25){
			print "\nFor ".$requests_from_platform .' requests, '. $line{(HOST)}." : ". $line{(USER_AGENT)}." has a request ratio of $request_ratio\n";
		}

		if ($requests_from_platform > 25 
			and ($requests_for_url_from_platform > 10)
			and (exists($suspicious_uas{$line{(USER_AGENT)}})
				or $line{(USER_AGENT)} =~ $suspicious_ua_re)
			){
			$_[KERNEL]->yield('block_host', \%line," because they look like a bot and keep asking for the same resource.");
		}

# THIS IS TOO AGGRESSIVE FOR NORMAL USE
# But it will catch the naive DDOS attacks (many requests for the same HTML page) we've been experiencing against citmedia
#
#	  	if($requests_for_url_from_host >= 3 && $line{(VHOST)} =~ m/citmedia/ && $request_ratio <= .3){
#			#IP is asking for this page more than 10 times
#			$_[KERNEL]->yield('block_host', \%line," because they are DDOS'ing citmedialaw");
#			return;
#		}

		if($requests_from_platform > 30 
			and ($request_ratio <= .2) 
			and (exists($suspicious_uas{$line{(USER_AGENT)}})
				or $line{(USER_AGENT)} =~ $suspicious_ua_re)
			){
			#If they have a suspicious UA, more than 30 requests and are skewing towards botness,
			#block 'em.
			$_[KERNEL]->yield('block_host', \%line," because they look like a bot and want a high percentage of HTML");
			return;
		}

		if($requests_from_platform > 50){
			#If their last 50 requests have been too quick and skewed towards botness, block'em.
			my ($last_request,$first_request) = $dbh->selectrow_array($statements->{last_x_requests_time_period},
				undef,
				($line{(HOST)}, $line{(USER_AGENT)},50));
			if($request_ratio <= .3 
				and (($last_request - $first_request) <= 100)
				){
				# works out to 2 seconds per page, where our crawl delay is set at 10 seconds
				# per page.
				$_[KERNEL]->yield('block_host',\%line," because they look like a bot, want HTML and request too fast.");
				return;
			}
		}

		if($requests_from_platform > 5){
			#If their last 5 requests have been too quick, skewed towards botness, and they look like a 'bot, block'em.
			my ($last_request,$first_request) = $dbh->selectrow_array($statements->{last_x_requests_time_period},
				undef,
				($line{(HOST)}, $line{(USER_AGENT)},5));
			if($request_ratio <= .2
				and (($last_request - $first_request) <= 2)
				and (exists($suspicious_uas{$line{(USER_AGENT)}})
						or $line{(USER_AGENT)} =~ $suspicious_ua_re)
				){
				# works out to 2.5 pages per second, where our crawl delay is set at 10 seconds
				print 'Block: ' . $line{(HOST)} . ' ' . $line{(USER_AGENT)} . " because they look like a bot, want HTML and request WAAAY too fast.";
				$_[KERNEL]->yield('block_host',\%line," because they look like a bot, want HTML and request WAY too fast.");
				return;
			}
		}

		if($requests_from_platform > 120 and $request_ratio == 1){
			#only binary requests for the last 120 requests - meaning they are violating our crawl-delay and
			#spidering only binary content.
			$_[KERNEL]->yield('block_host',\%line,' because they want only binary files for the last 100 requests.');
			return;
		}

		if($requests_from_platform > 300 and $request_ratio <= .1){
			#Ignoring time period, if they clearly only want HTML for more than 300 requests - block 'em
			#Remember that we purge requests older than 20 minutes, so 300 requests over 1200 seconds is
			#around 4 seconds between requests, exceeding our Crawl-Delay by more than 2.5 times.
			$_[KERNEL]->yield('block_host',\%line,' because they want almost entirely HTML for more than 300 requests.');
			return;
		}

		if(exists $o{debug} && $o{debug} > 2){
			print Dumper(\%line);
		}
	}
}


sub init_dbs{
	my $dbh = shift;

	my @tables = (
		'CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT, user_agent TEXT, url TEXT, rtime INTEGER, referer TEXT,bytes INTEGER)',
		'CREATE TABLE IF NOT EXISTS request_attributes(request_id INTEGER, atype TEXT)',
		'CREATE TABLE IF NOT EXISTS blocked(host TEXT, user_agent TEXT, btime INTEGER, reason TEXT)'
				);

	my $indexes = {
		'requests' =>['host','user_agent','url','rtime'],
		'request_attributes' => ['request_id','atype'],
		'blocked' => ['user_agent','btime']
		};

	foreach(@tables){
		$dbh->do($_);
	}

	foreach my $table(keys %$indexes){
		foreach my $column (@{$indexes->{$table}}){
				$dbh->do("CREATE INDEX IF NOT EXISTS ${table}_${column}s on $table(${column})");
		}
	}

	$dbh->do("CREATE UNIQUE INDEX IF NOT EXISTS blocked_hosts on blocked(host)");

	$dbh->do(q|
CREATE TRIGGER IF NOT EXISTS remove_request_attributes BEFORE DELETE ON requests
  FOR EACH ROW
    BEGIN
		DELETE FROM request_attributes WHERE request_id = old.id;
    END|);

}

sub init_statements{
	my %statements;
	$statements{insert_request} = $dbh->prepare('insert into requests(host,user_agent,rtime,referer,bytes,url) values (?,?,?,?,?,?)');
	$statements{insert_request_attribute} = $dbh->prepare('insert into request_attributes(request_id,atype) values(?,?)');
	$statements{get_platform_request_count} = $dbh->prepare('select count(*) as rcount from requests where user_agent = ? and host = ?');
	$statements{get_host_request_count} = $dbh->prepare('select count(*) as rcount from requests where host = ?');
	$statements{get_platform_request_count_by_attribute} = $dbh->prepare('select count(*) from request_attributes,requests where requests.user_agent = ? and requests.host = ? and requests.id = request_attributes.request_id and request_attributes.atype=?');
	$statements{get_platform_url_count} = $dbh->prepare('select count(url) from requests where user_agent = ? and host = ? and url = ?');
	$statements{get_host_url_count} = $dbh->prepare('select count(url) from requests where host = ? and url = ?');
	$statements{get_platform_total_request_time} = $dbh->prepare('select max(rtime) - min(rtime) from requests where host=? and user_agent = ?');
	$statements{block_host} = $dbh->prepare('replace into blocked(host,user_agent,btime,reason) values(?,?,?,?)');
	$statements{last_x_requests_time_period} = $dbh->prepare('select max(rtime) as last_request, min(rtime) as first_request from (select rtime from requests where host=? and user_agent=? order by rtime desc limit ?)');
	$statements{expire_requests} = $dbh->prepare('delete from requests where rtime <= ?');
	$statements{get_blocks_to_write} = $dbh->prepare('select host from blocked where btime >= ? group by host');
	return \%statements
}

sub usage{
	return qq|
Usage:
	./look_for_bad_bots.pl 
	This script used POE to watch an apache log file (in common log format) via Apache::LogRegex. It's designed to catch greedy - or misbehaving - "platforms," where a platform is the combination of User-Agent and REMOTE_HOST. It relies on POE's excellent multitasking support. 

	--debug=1		Set debug to 1,2 or 3 to increase debugging output.
	--help			This message.
	--logfile		The logfile (in apache common log format) to tail. We'll follow log rotation, no sweat.
	--dbfile		The sqlite file location. Defaults to a file called "bottracking.db" in the invocation directory.
	--ua_suspicious_re	A regular expression used to catch suspicious useragents.
	|;
}

=pod

=head1 look_for_bad_bots.pl

This script used POE to watch an apache log file (in common log format) via Apache::LogRegex. It's designed to catch greedy - or misbehaving - "platforms," where a platform is the combination of User-Agent and REMOTE_HOST. It relies on POE's excellent multitasking support. 

=head2 USAGE

 ./look_for_bad_bots.pl --help

should clue you in.

=head2 AUTHOR

Dan Collis-Puro
djcp at cyber dot law dot harvard dot edu

=head2 LICENSE

This script is licensed under the same terms as Perl itself.

=cut


