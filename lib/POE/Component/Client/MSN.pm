package POE::Component::Client::MSN;

use strict;
use vars qw($VERSION);
$VERSION = 0.01;

use vars qw($Default);
$Default = {
    port => 1863,
    hostname => 'messenger.hotmail.com',
};

use POE qw(Wheel::SocketFactory Wheel::ReadWrite Driver::SysRW Filter::Line Filter::Stream
	   Filter::MSN Component::Client::HTTP);
use POE::Component::Client::MSN::Command;
use HTTP::Request;
use Digest::MD5;
use Socket;
use URI::Escape ();

sub spawn {
    my($class, %args) = @_;
    $args{Alias} ||= 'msn';

    # session for myself
    POE::Session->create(
	inline_states => {
	    _start => \&_start,
	    _stop  => \&_stop,

	    # internals
	    _sock_up   => \&_sock_up,
	    _sock_down => \&_sock_down,
	    _sb_sock_up => \&_sb_sock_up,
	    _unregister => \&_unregister,

	    # API
	    notify     => \&notify,
	    register   => \&register,
	    unregister => \&unregister,
	    connect    => \&connect,
	    login      => \&login,

	    handle_event => \&handle_event,

	    # commands
	    VER => \&got_version,
	    CVR => \&got_client_version,
	    CHG => \&got_change_status,
	    XFR => \&got_xfer,
	    USR => \&got_user,
#	    LST => \&got_list,
#	    ILN => \&got_goes_online,
	    NLN => \&handle_common,
	    FLN => \&handle_common,
#	    RNG => \&got_ring,
	    MSG => \&handle_common,
	    CHL => \&got_challenge,
	    QRY => \&handle_common,
	    SYN => \&got_synchronization,
	    LSG => \&got_group,
	    LST => \&got_list,
#	    OUT => \&got_banned,

	    # states
	    got_1st_response => \&got_1st_response,
	    passport_login   => \&passport_login,
	    got_2nd_response => \&got_2nd_response,
	},
	args => [ \%args ],
    );

    # HTTP cliens session
    POE::Component::Client::HTTP->spawn(Agent => 'MSMSGS', Alias => 'ua');
}

sub _start {
    $_[KERNEL]->alias_set($_[ARG0]->{Alias});
    $_[HEAP]->{transaction} = 0;
}

sub _stop { }

sub register {
    my($kernel, $heap, $sender) = @_[KERNEL, HEAP, SENDER];
    $kernel->refcount_increment($sender->ID, __PACKAGE__);
    $heap->{listeners}->{$sender->ID} = 1;
}


sub unregister {
    my($kernel, $heap, $sender) = @_[KERNEL, HEAP, SENDER];
    $kernel->yield(_unregister => $sender->ID);
}

sub _unregister {
    my($kernel, $heap, $session) = @_[KERNEL, HEAP, ARG0];
    $kernel->refcount_decrement($session, __PACKAGE__);
    delete $heap->{listeners}->{$session};
}

sub notify {
    my($kernel, $heap, $name, $event) = @_[KERNEL, HEAP, ARG0, ARG1];
#    $event ||= POE::Component::Client::MSN::Event::Null->new;
    $kernel->post($_ => "msn_$name" => $event->args) for keys %{$heap->{listeners}};
}

sub connect {
    my($kernel, $heap, $args) = @_[KERNEL, HEAP, ARG0];

    # set up parameters
    $heap->{$_} = $args->{$_}
	for qw(username password);
    $heap->{$_} = $args->{$_} || $Default->{$_}
	for qw(hostname port);

    return if $heap->{sock};
    $heap->{sock} = POE::Wheel::SocketFactory->new(
	SocketDomain => AF_INET,
	SocketType => SOCK_STREAM,
	SocketProtocol => 'tcp',
	RemoteAddress => $heap->{hostname},
	RemotePort => $heap->{port},
	SuccessEvent => '_sock_up',
	FailureEvent => '_sock_failed',
    );
}

sub _sock_up {
    my($kernel, $heap, $socket) = @_[KERNEL, HEAP, ARG0];

    # new ReadWrite wheel for the socket
    $heap->{sock} = POE::Wheel::ReadWrite->new(
	Handle => $socket,
	Driver => POE::Driver::SysRW->new,
	Filter => POE::Filter::MSN->new,
	ErrorEvent => '_sock_down',
    );
    $heap->{sock}->event(InputEvent => 'handle_event');
    $heap->{sock}->put(
	POE::Component::Client::MSN::Command->new(VER => "MSNP9 CVR0" => $heap),
    );
}


sub _sock_failed {
    my($kernel, $heap) = @_[KERNEL, HEAP];
    $kernel->yield(notify => socket_error => ());
    for my $session (keys %{$heap->{listeners}}) {
        $kernel->yield(_unregister => $session);
    }
}

sub _sock_down {
    my($kernel, $heap) = @_[KERNEL, HEAP];
    warn "sock is down";
    delete $heap->{sock};
}

sub handle_event {
    my($kernel, $heap, $command) = @_[KERNEL, HEAP, ARG0];
    if ($command->errcode) {
	warn "got error: ", $command->errcode;
	$kernel->yield(notiy => got_error => $command);
    } else {
	$kernel->yield($command->name, $command);
    }
}

sub got_version {
    $_[HEAP]->{sock}->put(
	POE::Component::Client::MSN::Command->new(CVR => "0x0409 winnt 5.1 i386 MSNMSGR 6.0.0602 MSMSGS $_[HEAP]->{username}" => $_[HEAP]),
    );
}

sub got_client_version {
    $_[HEAP]->{sock}->put(
	POE::Component::Client::MSN::Command->new(USR => "TWN I $_[HEAP]->{username}" => $_[HEAP]),
    );
}

sub got_xfer {
    my($kernel, $heap, $command) = @_[KERNEL, HEAP, ARG0];
    if ($command->args->[0] eq 'NS') {
	@{$heap}{qw(hostname port)} = split /:/, $command->args->[1];
	# switch to Notification Server
	$_[HEAP]->{sock} = POE::Wheel::SocketFactory->new(
	    SocketDomain => AF_INET,
	    SocketType => SOCK_STREAM,
	    SocketProtocol => 'tcp',
	    RemoteAddress => $heap->{hostname},
	    RemotePort => $heap->{port},
	    SuccessEvent => '_sock_up',
	    FailureEvent => '_sock_failed',
	);
    }
}

sub got_user {
    my $event = $_[ARG0];
    if ($event->args->[1] eq 'S') {
	$_[HEAP]->{cookie} = $event->args->[2];
	my $request = HTTP::Request->new(GET => 'https://nexus.passport.com/rdr/pprdr.asp');
	$_[KERNEL]->post(ua => request => got_1st_response => $request);
    }
    elsif ($event->args->[0] eq 'OK') {
	$_[KERNEL]->yield(notify => signin => $event);
	# set initial status
	$_[HEAP]->{sock}->put(
	    POE::Component::Client::MSN::Command->new(CHG => "NLN" => $_[HEAP]),
	);
    }
}
#	$_[HEAP]->{sock}->put(
#	    POE::Component::Client::MSN::Command->new(USR => "MD5 S $response" => $_[HEAP]),
#	);
#    }
#    elsif ($_[ARG0]->args->[0] eq 'OK') {
#	$_[HEAP]->{sock}->put(
#	    POE::Component::Client::MSN::Command->new(CHG => 'NLN' => $_[HEAP]),
#	);
#	$_[HEAP]->{sock}->put(
#	    POE::Component::Client::MSN::Command->new(SYN => 0 => $_[HEAP]),
#	);
#    }

sub got_1st_response {
    my($request_packet, $response_packet) = @_[ARG0, ARG1];
    my $response = $response_packet->[0];

    my $passport_url = (_fake_header($response, 'PassportURLs') =~ /DALogin=(.*?),/)[0]
	or warn $response->as_string;
    if ($passport_url) {
	$_[KERNEL]->yield(passport_login => "https://$passport_url");
    }
}

sub passport_login {
    my $passport_url = $_[ARG0];
    my $request = HTTP::Request->new(GET => $passport_url);
    my $sign_in  = URI::Escape::uri_escape($_[HEAP]->{username});
    my $password = URI::Escape::uri_escape($_[HEAP]->{password});
    $request->header(Authorization => "Passport1.4 OrgVerb=GET,OrgURL=http%3A%2F%2Fmessenger%2Emsn%2Ecom,sign-in=$sign_in,pwd=$password,$_[HEAP]->{cookie}");
    $_[KERNEL]->post(ua => request => got_2nd_response => $request);
}

sub got_2nd_response {
    my($request_packet, $response_packet) = @_[ARG0, ARG1];
    my $response = $response_packet->[0];
#    my $auth_info = $response->header('Authentication-Info');
    my $auth_info = _fake_header($response, 'Authentication-Info');
    if ($auth_info =~ /da-status=redir/) {
	my $new_location = _fake_header($response, 'Location');
	$_[KERNEL]->yield(passport_login => $new_location);
    }
    elsif ($auth_info =~ /PP='(.*?)'/) {
	my $credential = $1;
	$_[HEAP]->{sock}->put(
	    POE::Component::Client::MSN::Command->new(USR => "TWN S $credential" => $_[HEAP]),
	);
    }
}

sub _fake_header {
    my($response, $key) = @_;
    # seems to be a bug. it's in body
    return $response->header($key) || ($response->content =~ /^$key: (.*)$/m)[0];
}

sub handle_common {
    my $event = $_[ARG0]->name;
    $_[KERNEL]->yield(notify => "got_$event", $_[ARG0]);
}

sub got_challenge {
    my $challenge = $_[ARG0]->args->[0];
    my $response = sprintf "%s %d\r\n%s",
	'msmsgs@msnmsgr.com', 32, Digest::MD5::md5_hex($challenge . "Q1P7W2E4J9R8U3S5");
    $_[HEAP]->{sock}->put(
	POE::Component::Client::MSN::Command->new(QRY => $response => $_[HEAP], 1),
    );
}

sub got_change_status {
    if ($_[ARG0]->args->[0] eq 'NLN') {
	# normal status
	my $cl_version = $_[HEAP]->{CL_version} || 0;
	$_[HEAP]->{sock}->put(
	    POE::Component::Client::MSN::Command->new(SYN => $cl_version => $_[HEAP]),
	);
    }
}

sub got_synchronization {
    my($version, $lst_num, $lsg_num) = $_[ARG0]->args;
    if (!$_[HEAP]->{CL_version} || $version > $_[HEAP]->{CL_version}) {
	warn "synchronize CL version to $version";
	$_[HEAP]->{CL_version} = $version;
	$_[KERNEL]->yield(notify => 'got_synchronization' => $_[ARG0]);
    }
}

sub got_list {
    my($account, $screen_name, $listmask, $groups) = $_[ARG0]->args;
    my @groups = split /,/, $groups;
    $_[HEAP]->{buddies}->{$account} = {
	screen_name => $screen_name,
	listmask    => $listmask,
	groups      => $groups,
    };
    $_[KERNEL]->yield(notify => 'got_list' => $_[ARG0]);
}

sub got_group {
    my($group, $gid) = $_[ARG0]->args;
    $_[HEAP]->{groups}->{$gid} = $group;
    $_[KERNEL]->yield(notify => 'got_group' => $_[ARG0]);
}



=pod

sub got_list {
    my($kernel, $heap, $command) = @_[KERNEL, HEAP, ARG0];
    my($type, $buddy, $nickname) = ($command->args)[0,4,5];
    if ($type eq 'FL') {	# Forward List
	$heap->{buddies}->{$buddy} = $nickname;
    }
    $kernel->yield(notify => buddy_list => $command);
}

sub got_ring {
    my($kernel, $heap, $session, $command) = @_[KERNEL, HEAP, SESSION, ARG0];
    POE::Session->create(
	inline_states => {
	    _start => \&sb_start,
	    _sb_sock_up => \&sb_sock_up,
	    _sb_sock_down => \&sb_sock_down,
	    handle_event => \&sb_handle_event,
	    MSG => \&sb_got_message,
	    send_message => \&sb_send_message,
	},
	args => [ $command, $session->ID, $heap ],
    );
}

sub sb_start {
    my($kernel, $heap, $command, $parent, $old_heap) = @_[KERNEL, HEAP, ARG0, ARG1, ARG2];
    $heap->{parent} = $parent;
    $heap->{session} = $command->transaction;
    $heap->{transaction} = $old_heap->{transaction} + 1;
    $heap->{username} = $old_heap->{username};
    @{$heap}{qw(hostname port)} = split /:/, $command->args->[0];
    $heap->{key} = $command->args->[2];
    $heap->{buddy} = $command->args->[3];
    $heap->{sock} = POE::Wheel::SocketFactory->new(
	SocketDomain => AF_INET,
	SocketType => SOCK_STREAM,
	SocketProtocol => 'tcp',
	RemoteAddress => $heap->{hostname},
	RemotePort => $heap->{port},
	SuccessEvent => '_sb_sock_up',
	FailureEvent => '_sb_sock_failed',
    );
}

sub sb_sock_up {
    my($kernel, $heap, $socket) = @_[KERNEL, HEAP, ARG0];
    $heap->{sock} = POE::Wheel::ReadWrite->new(
	Handle => $socket,
	Driver => POE::Driver::SysRW->new,
	Filter => POE::Filter::MSN->new,
	ErrorEvent => '_sb_sock_down',
    );
    $heap->{sock}->event(InputEvent => 'handle_event');
    $heap->{sock}->put(
	POE::Component::Client::MSN::Command->new(
	    ANS => "$heap->{username} $heap->{key} $heap->{session}" => $heap,
	),
    );
}

sub sb_sock_down {
    delete $_[HEAP]->{sock};
}

sub sb_handle_event {
    my($kernel, $heap, $command) = @_[KERNEL, HEAP, ARG0];
    $kernel->yield($command->name, $command);
}

sub sb_got_message {
    my($kernel, $heap, $command) = @_[KERNEL, HEAP, ARG0];
    $kernel->post($heap->{parent} => notify => got_message => $command);
}

sub sb_send_message {
    my($kernel, $heap, $args) = @_[KERNEL, HEAP, ARG0];
    
}
=cut

1;
__END__

=head1 NAME

POE::Component::Client::MSN - POE Component for MSN Messenger

=head1 SYNOPSIS

  use POE qw(Component::Client::MSN);

  # spawn MSN session
  POE::Component::Client::MSN->spawn(Alias => 'msn');

  # register your session as MSN observer
  $kernel->post(msn => 'register');
  # tell MSN how to connect servers
  $kernel->post(msn => connect => {
      username => 'yourname',
      password => 'xxxxxxxx',
  });

  sub msn_goes_online {
      my $event = $_[ARG0];
      print $event->username, " goes online.\n";
  }

  $poe_kernel->run;

=head1 DESCRIPTION

POE::Component::Client::MSN is a POE component to connect MSN Messenger server.

=head1 AUTHOR

Tatsuhiko Miyagawa E<lt>miyagawa@bulknews.netE<gt>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 SEE ALSO

L<POE>, L<POE::Component::YahooMessenger>

http://www.hypothetic.org/docs/msn/research/msnp9.php

http://www.chat.solidhouse.com/

=cut
