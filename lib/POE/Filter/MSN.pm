package POE::Filter::MSN;
use strict;

use POE qw(Component::Client::MSN::Command);

use vars qw($Debug);
$Debug = 1;

sub Dumper { require Data::Dumper; local $Data::Dumper::Indent = 1; Data::Dumper::Dumper(@_) }

sub new {
    my $class = shift;
    bless {
	buffer => '',
	get_state => 'line',
	body_info => {},
    }, $class;
}

sub get {
    my($self, $stream) = @_;
    $self->{buffer} .= join '', @$stream;
    my @commands;
    if ($self->{get_state} eq 'line') {
	while ($self->{buffer} =~ s/^(.{3}) (?:(\d+) )?(.*?)\r\n//){
	    my $command =  POE::Component::Client::MSN::Command->new($1, $3, $2);
	    if ($command->name eq 'MSG') {
		# switch to body
		$self->{get_state} = 'body';
		$self->{body_info} = {
		    command => $command,
		    length  => $command->args->[2],
		};
		last;
	    } else {
		push @commands, $command;
	    }
	}
    }

    if ($self->{get_state} eq 'body') {
	if (length($self->{buffer}) < $self->{body_info}->{length}) {
	    # not enough bytes
	    $Debug and warn Dumper \@commands;
	    return \@commands;
	}
	my $message = substr($self->{buffer}, 0, $self->{body_info}->{length}, '');
	my $command = $self->{body_info}->{command};
	$command->message($message);
	push @commands, $command;

	# switch to head
	$self->{get_state} = 'line';
    }
    $Debug and warn "GET: ", Dumper \@commands;
    return \@commands;
}

sub put {
    my($self, $commands) = @_;
    return [ map $self->_put($_), @$commands ];
}

sub _put {
    my($self, $command) = @_;
    $Debug and warn "PUT: ", Dumper $command;
    return sprintf "%s %d %s%s",
	$command->name, $command->transaction, $command->data, ($command->no_newline ? '' : "\r\n");
}

1;

