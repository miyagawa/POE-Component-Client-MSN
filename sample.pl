#!/usr/local/bin/perl -w
# $Id$
#
# Tatsuhiko Miyagawa <miyagawa@edge.jp>
# EDGE, Co.,Ltd.
#

use strict;

sub POE::Kernel::ASSERT_DEFAULT { $ENV{POE_ASSERT} || 0 }
sub POE::Kernel::TRACE_DEFAULT  { $ENV{POE_TRACE} || 0 }
sub POE::Kernel::TRACE_EVENTS   { $ENV{POE_EVENTS} || 0 }

use POE qw(Component::Client::MSN Component::TSTP);

my($user, $pw) = @ARGV;

# for Ctrl-Z
POE::Component::TSTP->create();

# spawn MSN session
POE::Component::Client::MSN->spawn(Alias => 'msn');

POE::Session->create(
    inline_states =>  {
	_start => sub {
	    my $kernel = $_[KERNEL];
	    # register your session as MSN observer
	    $kernel->post(msn => 'register');
	    # tell MSN how to connect servers
	    $kernel->post(msn => connect => {
		username => $user,
		password => $pw,
	    });
	},
	msn_goes_online => \&msn_goes_online,
	msn_signin => \&msn_signin,
    },
);


sub msn_signin {
    my($status, $account, $screen_name, $email_verified) = @_[ARG0..$#_];
    warn "online as $screen_name ($account)";
}


sub msn_goes_online {
    my $event = $_[ARG0];

}

$poe_kernel->run;
