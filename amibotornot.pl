#!/usr/bin/perl

=pod

=head1 look_for_bad_bots.pl

This script uses POE to watch an apache log file (in common log format) via Apache::LogRegex. It's designed to catch greedy - or misbehaving - "platforms," where a platform is the combination of User-Agent and REMOTE_HOST. It relies on POE's excellent multitasking support. 

=head2 USAGE

 amibotornot.pl --help

should clue you in.

=cut

=head2 REQUIREMENTS
 
Apache, POE and POE::Wheel::FollowTail, Apache::LogRegex, Data::Dumper, Getopt::Long, DBI and DBD::SQLite, DateTime and DateTime::Format::HTTP, and DB_File. 

=cut

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
	'rewrite_dbm_file=s',
	'ua_suspicious_re=s',
	'ua_whitelist_re=s',
	'host_whitelist_re=s',
        'max_block_time=i',
        'request_decay=i'
	);

if($o{help}){
	print usage();
}

$o{max_block_time} ||= 1200;
$o{request_decay} ||= 1200;
my $dbfile = $o{dbfile} || 'bottracking.db';
$o{rewrite_dbm_file} ||= '/web/ethan/wpmu/conf/apache2/badplatforms.dbm';

my $dbh = DBI->connect("dbi:SQLite:dbname=$dbfile","","",{ RaiseError => 1, AutoCommit => 0 }) or croak($DBI::errstr);
use DateTime::Format::HTTP;
my $dt_class = 'DateTime::Format::HTTP';

init_dbs($dbh);
my $statements = init_statements($dbh);

my $requests_processed = 0;

$|=1;

#These are exactly matched.
my %suspicious_uas = (
	'Mozilla/4.0' => 1,
	'Mozilla/5.0' => 1,	
	'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)' => 1,
	'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)' => 1,
	'Mozilla/4.0 (compatible;)' => 1,
	'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9)' => 1,
	'Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)' => 1,
	'Mozilla/5.0 Firefox/3.0.5' => 1,
	'Mozilla/4.0 (compatible; MSIE 6.0; MSIE 5.5; Windows NT 4.0) Opera 7.0 [en]' => 1,
	'Opera' => 1,
	'-' => 1,
	'0' => 1
);

my $suspicious_ua_re = (exists($o{ua_suspicious_re})) ? qr/$o{ua_suspicious_re}/i : qr/shelob|libcurl|mechanize/i;
my $useragent_whitelist = (exists($o{ua_whitelist_re})) ? qr/$o{ua_whitelist_re}/i : qr/loc\.gov|googlebot|slurp|msnbot|google\.com\/feedfetch|ask jeeves|ia_archiver|bloglines|feedhub|spinn3r|livejournal/i;
my $host_whitelist = (exists($o{host_whitelist_re})) ? qr/$o{host_whitelist_re}/i : qr/^(128\.103\.6|192\.168|140\.247)/i;

my $lr = Apache::LogRegex->new($o{log_format} || '%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"');

my $FILENAME = $o{logfile} || '/web/ethan/wpmu/logs/apache2/access.log';

POE::Session->create(
  inline_states =>
    {
      _start => \&log_handler ,
      got_line => \&process_line ,
      expire_requests => \&expire_requests,
      write_block_file => \&write_block_file,
      block_platform => \&block_platform
    },
);

sub log_handler{
	$_[HEAP]->{wheel} =
	POE::Wheel::FollowTail->new(
		Filename => $FILENAME,
		InputEvent => 'got_line'
	);
	$_[KERNEL]->alarm( write_block_file => time() + 60);
	$_[KERNEL]->alarm( expire_requests => time() + 90);
}

$poe_kernel->run();

sub write_block_file{
	if(defined $o{debug}){
		print "Writing block file . . ." . time() ."\n";
	}
	#Ignore blocks older than 20 minutes.
	my $platforms_to_block = $dbh->selectall_arrayref($statements->{get_blocks_to_write}, {Columns => {}}, (time - $o{max_block_time}));

=pod

=head2 APACHE INTEGRATION

amibotornot ultimately ends up writing out a dbm file consisting of a hash with $host.$user_agent as keys and "badplatform" as the value. The value isn't important, the keys are.

This hash is then linked into apache in virtualhost (or global) context, with a set of rules similar to:

 RewriteMap badplatforms dbm:/web/ethan/wpmu/conf/apache2/badplatforms.dbm
 RewriteCond ${badplatforms:%{REMOTE_ADDR}%{HTTP_USER_AGENT}} badplatform
 RewriteRule .* - [F,L]

The "F" rewrite rule target makes apache return a 403 error, obviously you can customize the output of apache's 403 error page.

=cut

	my $output;
	my %hash;
	tie(%hash, 'DB_File', $o{rewrite_dbm_file}) or croak($!);
	%hash = ();
	foreach my $to_block(@$platforms_to_block){
		$hash{$to_block->{host}.$to_block->{user_agent}} = 'badplatform';
	}
	untie %hash;
	#Reschedule for a minute out.
	$_[KERNEL]->alarm( write_block_file => time() + 60);

}

sub expire_requests{
	if(defined $o{debug}){
		print "Expiring requests and committing. . ." . time() ."\n";
	}
	$statements->{expire_requests}->execute( time - $o{request_decay} );
	$_[KERNEL]->alarm( expire_requests => time() + 90);
	$dbh->commit();
}


sub whitelisted{
	my $line = shift;
	if(($line->{(HOST)} =~ $host_whitelist) || ($line->{(USER_AGENT)} =~ $useragent_whitelist)){
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

	if($line->{(REQUEST)} =~ /\.jpe?g|\.css|\.png|\.bmp|\.gif|\.mp3?|\.mov|\.m4v|\.mpg|\.ogg|\.xlsx?|\.docx?|\.pptx?|\.js|\.swf|\.jar|\.ico|\.pdf/i){
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

sub block_platform{
	my ($line,$reason) = ($_[ARG0], $_[ARG1]);
	$statements->{block_platform}->execute($line->{(HOST)}, $line->{(USER_AGENT)},time,$reason);
	if(exists $o{debug}){
		print "Block: ".$line->{(HOST)}. $reason."\n";
	}
	$_[KERNEL]->alarm( write_block_file => time() - 1);
}

sub calculate_request_ratio{
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
		$requests_processed++;

		return if whitelisted(\%line);
		my $method = substr($line{(REQUEST)},0,4);
		return unless($method eq 'GET ' || $method eq 'POST' || $method eq 'HEAD');
		
		return unless(substr($line{(STATUS)},0,1) == 2);

		if(exists $o{debug}){
			print '.';
		}
		$statements->{insert_request}->execute($line{(HOST)},$line{(USER_AGENT)},apache_to_epoch_time($line{(TIME)}),$line{(HTTP_REFERER)},$line{(BYTES)},$line{(REQUEST)});
		my $request_id = $dbh->func('last_insert_rowid');

		track_basic_request_parameters_dbi($request_id,\%line);

		my ($requests_from_platform) = $dbh->selectrow_array($statements->{get_platform_request_count}, undef,($line{(USER_AGENT)}, $line{(HOST)}));
		my ($requests_for_url_from_platform) = $dbh->selectrow_array($statements->{get_platform_url_count}, undef,($line{(USER_AGENT)}, $line{(HOST)},$line{(REQUEST)}));

		if(exists($o{debug}) && $o{debug} > 1){
			print "$requests_from_platform requests from ". $line{(HOST)} ." : ". $line{(USER_AGENT)}."\n";
		}

		my $request_ratio = undef;

		if($requests_from_platform > 50){
			$request_ratio = calculate_request_ratio($line{(HOST)},$line{(USER_AGENT)});
		}

		if(exists $o{debug} && defined($request_ratio)){
			print "\nFor ".$requests_from_platform .' requests, '. $line{(HOST)}." : ". $line{(USER_AGENT)}." has a request ratio of $request_ratio\n";
		}

		if ($requests_from_platform > 50 
			and ($request_ratio <= .3) 
			and ($requests_for_url_from_platform > 25)){
			print "We want to block: ".$line{(HOST)}." because they look like a bot and keep asking for the same resource\n";
			#$_[KERNEL]->yield('block_platform', \%line," because they look like a bot and keep asking for the same resource.");
		}
	  
		if($requests_from_platform > 50 
			and ($request_ratio <= .3) 
			and (exists($suspicious_uas{$line{(USER_AGENT)}})
				or $line{(USER_AGENT)} =~ $suspicious_ua_re)
			){
			#If they have a suspicious UA, more than 50 requests and are skewing towards botness,
			#block 'em.
			$_[KERNEL]->yield('block_platform', \%line," because they look like a bot and want a high percentage of HTML");
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
				$_[KERNEL]->yield('block_platform',\%line," because they look like a bot, want HTML and request too fast.");
				return;
			}
		}

		if($requests_from_platform > 120 and $request_ratio == 1){
			#only binary requests for the last 120 requests - meaning they are violating our crawl-delay and
			#spidering only binary content.
			$_[KERNEL]->yield('block_platform',\%line,' because they want only binary files for the last 100 requests.');
			return;
		}


		if($requests_from_platform > 300 and $request_ratio <= .1){
			#Ignoring time period, if they clearly only want HTML for more than 300 requests - block 'em
			#Remember that we purge requests older than 20 minutes, so 300 requests over 1200 seconds is
			#around 4 seconds between requests, exceeding our Crawl-Delay by more than 2.5 times.
			$_[KERNEL]->yield('block_platform',\%line,' because they want almost entirely HTML for more than 300 requests.');
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

	$dbh->do("CREATE UNIQUE INDEX IF NOT EXISTS blocked_platforms on blocked(host,user_agent)");

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
	$statements{get_platform_request_count_by_attribute} = $dbh->prepare('select count(*) from request_attributes,requests where requests.user_agent = ? and requests.host = ? and requests.id = request_attributes.request_id and request_attributes.atype=?');
	$statements{get_platform_url_count} = $dbh->prepare('select count(url) from requests where user_agent = ? and host = ? and url = ?');
	$statements{get_platform_total_request_time} = $dbh->prepare('select max(rtime) - min(rtime) from requests where host=? and user_agent = ?');
	$statements{block_platform} = $dbh->prepare('replace into blocked(host,user_agent,btime,reason) values(?,?,?,?)');
        $statements{last_x_requests_time_period} = $dbh->prepare('select max(rtime) as last_request, min(rtime) as first_request from (select rtime from requests where host=? and user_agent=? order by rtime desc limit ?)');
	$statements{expire_requests} = $dbh->prepare('delete from requests where rtime <= ?');
	$statements{get_blocks_to_write} = $dbh->prepare('select host,user_agent from blocked where btime >= ?');
	return \%statements
}

sub usage{
	return qq|
Usage:
	amibotornot.pl 
    This script uses POE to watch an apache log file (in common log format) via Apache::LogRegex. It's designed to catch greedy - or misbehaving - "platforms," where a platform is the combination of User-Agent and REMOTE_HOST. It relies on POE's excellent multitasking support. 
    It allows users to whitelist based on IP or  UserAgents. You can also tag UserAgents as "suspicious", which makes us a bit more likely to block based on behavioral tests.
    This script integrates with the Apache server through a dbm-based RewriteMap - when a "platform" is caught, we add them into the DBM file and the rewrite rule returns a 403.  We only inspect requests that return a 200 status code and block clients for up to 20 minutes.
    We write the block DBM file every time we find a new platform to block, or every minute - whichever comes first. As alluded to above, platform blocks expire every 20 minutes.


	--debug=1		Set debug to 1,2 or 3 to increase debugging output.
	--help			This message.
	--logfile		The logfile (in apache common log format) to tail. We'll follow log rotation, no sweat.
	--dbfile		The sqlite file location. Defaults to a file called "bottracking.db" in the invocation directory.
       	--rewrite_dbm_file	The location of the DB_File block file managed by this script, which is then linked into an apache virtualhost.
	--ua_suspicious_re	A regular expression used to catch suspicious useragents.
        --ua_whitelist_re       A regular expression used to whitelist based on UserAgent.
        --host_whitelist_re     A regular expression used to whitelist based on IP address.
        --log_format            The apache LogFormat string - this is used by Apache::LogRegex.
        --max_block_time        The maximum number of seconds to block a misbehaving platform : 1200 seconds defaultly.
        --request_decay         The maximum age of requests to stay aware of - this should probably equal max_block_time.
	|;
}

=pod 

=head2 AUTHOR

Dan Collis-Puro
djcp at cyber dot law dot harvard dot edu

=head2 LICENSE

This script is licensed under the same terms as Perl itself.

=cut
