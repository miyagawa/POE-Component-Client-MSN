package POE::Component::Client::MSN::Command;
use strict;
use URI::Escape;
use Mail::Internet;

# XXX Validation should be done
# Transaction ID: 4294967295
# Friendly Name: 129 characters
# Messages: 1664 characters
# Forward List: 150 buddies
# Number of groups: 30

sub new {
    my($class, $name, $data, $stuff, $no_newline) = @_;
    my $transaction = ref($stuff) eq 'HASH' # heap?
	? $stuff->{transaction}++ : $stuff;

    # error is in \d\d\d
    my $errcode;
    if ($name =~ /^\d{3}$/) {
	$errcode = $name;
    }

    bless {
	name        => $name,
	data        => $data,
	errcode     => $errcode,
	transaction => $transaction,
	message     => undef,
	_args       => undef,
	no_newline  => $no_newline,
    }, $class;
}

sub name { shift->{name} }
sub data { shift->{data} }
sub errcode { shift->{errcode} }
sub transaction { shift->{transaction} }
sub no_newline { shift->{no_newline} }


sub message {
    my $self = shift;
    if (@_) {
	$self->{message} = Mail::Internet->new([ split /\r\n/, shift ]);
    }
    return $self->{message};
}

sub body {
    my $self = shift;
    return join '', map "$_\n", @{$self->message->body};
}

sub header {
    my($self, $key) = @_;
    my $value = $self->message->head->get($key);
    chomp($value);
    return $value;
}

sub args {
    my $self = shift;
    $self->{_args} ||= [ map URI::Escape::uri_unescape($_), split / /, $self->data ];
    return wantarray ? @{$self->{_args}} : $self->{_args};
}

1;
