#!/usr/bin/perl
use strict;
use Test::More tests => 10;

use DJabberd;
DJabberd::Log::set_logger("main");
use DJabberd::VHost;
use DJabberd::Authen::AllowedUsers;
use DJabberd::Authen::StaticPassword;
use DJabberd::RosterStorage::InMemoryOnly;
use DJabberd::RosterItem;

use DJabberd::Plugin::PEP;

my $domain = "example.com";
my $dother = "example.org";

my $plugs = [
            DJabberd::Authen::AllowedUsers->new(policy => "deny",
                                                allowedusers => [qw(partya partyb)]),
            DJabberd::Authen::StaticPassword->new(password => "password"),
            DJabberd::RosterStorage::InMemoryOnly->new(),
	    DJabberd::Plugin::PEP->new(),
            DJabberd::Delivery::Local->new,
            DJabberd::Delivery::S2S->new
	];
my $vhost = DJabberd::VHost->new(
            server_name => $domain,
            s2s         => 1,
            plugins     => $plugs,
        );

my ($me, $she) = ('partya', 'partyb');
my ($my, $her) = ('partya@'.$domain, 'partyb@'.$dother);
my $sub = DJabberd::Subscription->new();
my $ri = DJabberd::RosterItem->new( jid => $her, subscription => $sub);

sub disco {
    $vhost->run_hook_chain(
	phase=> "DiscoBare",
	args     => [ 'iq', $_[0], DJabberd::JID->new("$my/test"), $her, $ri ],
	methods => {
	    addFeatures => sub {
		my $cb = shift;
		for my $ns (@_) {
		    if(!ref($ns)) {
			if ($ns eq 'http://jabber.org/protocol/pubsub#publish' ||
			    $ns eq 'http://jabber.org/protocol/pubsub#auto-create' ||
			    $ns eq 'http://jabber.org/protocol/pubsub#auto-subscribe' ||
			    $ns eq 'http://jabber.org/protocol/pubsub#access-presence' ||
			    $ns eq 'http://jabber.org/protocol/pubsub#filtered-notifications')
			{
			    ok(1, $ns);
			}
		    }
		}
		$cb->reset;
		$cb->decline;
	    },
	    addItems => sub {
		my $cb = shift;
		ok(!@_, 'Nothing yet, but called');
	    },
	}
    );
}
disco('info');
disco('items');
$sub->set_from(1);
disco('info');
disco('items');
