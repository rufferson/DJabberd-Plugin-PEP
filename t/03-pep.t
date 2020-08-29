#!/usr/bin/perl
use strict;
use Test::More tests => 23;

use DJabberd;
DJabberd::Log::set_logger("main");
use DJabberd::VHost;
use DJabberd::Authen::AllowedUsers;
use DJabberd::Authen::StaticPassword;
use DJabberd::RosterStorage::InMemoryOnly;

use DJabberd::Plugin::PEP;

my $domain = "example.com";
my $dother = "example.org";

my $pep = DJabberd::Plugin::PEP->new();
$pep->finalize();

my $plugs = [
            DJabberd::Authen::AllowedUsers->new(policy => "deny",
                                                allowedusers => [qw(partya partyb)]),
            DJabberd::Authen::StaticPassword->new(password => "password"),
            DJabberd::RosterStorage::InMemoryOnly->new(),
	    $pep,
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
my $ecod;

my $res_ok = sub { like($_[0], qr/^<iq[^>]+type=['"]result['"]/, "Is Result") };
my $err_ok = sub { like($_[0], qr/^<iq[^>]+type=['"]error['"]/,  "Is Error") };
my $unauth = sub { like($_[0], qr/<error[^<]+<not-allowed\s+/m,  "Is AuthError") };
my $ecodok = sub { like($_[0], qr/<error[^>]+code=['"]($ecod)['"]/, "Is Error $ecod") };
my $notimplemented = sub { like($_[0], qr/<error[^<]+<feature-not-implemented/, 'Not implemented') };

my $pepevt = sub { ok(($_[0]->element eq '{jabber:client}message' and $_[0]->attr('{}type') eq 'headline'), "Is PEP event") or diag($_[0]->as_xml) };


my $nop = sub {};
my ($wtest, $rtest, $stest, $dtest) = ($nop, $nop, $nop, $nop);
my $psq = DJabberd::XMLElement->new('http://jabber.org/protocol/pubsub', 'pubsub', { xmlns => 'http://jabber.org/protocol/pubsub' });
my $iq = DJabberd::IQ->new('jabber:client', 'iq',
    {
	xmlns=> 'jabber:client',
	'{}type' => 'set',
	'{}to' => $my,
	'{}id' => 'iq1',
    },
    [
	$psq,
    ]);
# vhost, jid, write, receive, send
my $fc = FakeCon->new($vhost, DJabberd::JID->new("$my/test"), 
    sub { $wtest->(${$_[1]}) },
    sub { $rtest->(@_) },
    sub { $stest->(@_) }
);
$iq->set_connection($fc);

my $cb = DJabberd::Callback->new({registered=>sub{}});
$vhost->register_jid(DJabberd::JID->new($my), 'test', $fc, $cb);

$vhost->register_hook("deliver", sub {
    my ($v, $cb, $stanza) = @_;
    $dtest->($stanza);
    $cb->delivered();
}, 'DJabberd::Delivery::Local'); # Cheat to intercept S2S delivery

# Publish and create open-access node - should receive pep event on self
# Prepare published data
my $psp = DJabberd::XMLElement->new(undef, 'publish', { '{}node' => 'urn:xmpp:omemo:1:devices' }, []);
my $item = DJabberd::XMLElement->new(undef, 'item', { '{}id' => 'current' }, []);
my $devs = DJabberd::XMLElement->new('urn:xmpp:omemo:1', 'devices', {xmlns=>'urn:xmpp:omemo:1'}, [
    DJabberd::XMLElement->new(undef, 'device', {'{}id'=>'10', '{}label' => 'My Precious'},[])
]);
$item->push_child($devs);
$psp->push_child($item);
# Prepare publish options
my $pbo = DJabberd::XMLElement->new(undef, 'publish-options', {}, []);
my $frm = DJabberd::Form->new('submit', [
	{var=>'FORM_TYPE', value=>['http://jabber.org/protocol/pubsub#publish-options'], type=>'hidden'},
	{var=>'pubsub#access_model', value=>['open']},
    ]);
my $xfr = $frm->as_element;
$pbo->push_child($xfr);

$psq->push_child($pbo);
$psq->push_child($psp);
$wtest = $res_ok;
$stest = sub {
    my ($e) = @_;
    $pepevt->($e);
    ok((grep{$_->element eq '{http://jabber.org/protocol/address}addresses'}$e->children_elements), "Has addressing");
};
$fc->push_c2s($iq);
$pbo->remove_child($xfr);
$psq->remove_child($pbo);

# Send directed presence
my $dinfo = DJabberd::XMLElement->new('http://jabber.org/protocol/disco#info', 'query',
    {xmlns=>'http://jabber.org/protocol/disco#info'}, [
    DJabberd::XMLElement->new(undef, 'identity', {'{}category'=>'client', '{}type'=>'pc'}),
    DJabberd::XMLElement->new(undef, 'feature', {'{}var'=>'urn:xmpp:omemo:1'}),
    DJabberd::XMLElement->new(undef, 'feature', {'{}var'=>'urn:xmpp:omemo:1:devices+notify'}),
    DJabberd::XMLElement->new(undef, 'feature', {'{}var'=>'urn:xmpp:omemo:1:bundles+notify'}),
    DJabberd::XMLElement->new(undef, 'feature', {'{}var'=>'urn:xmpp:avatar:metadata+notify'}),
    DJabberd::XMLElement->new(undef, 'feature', {'{}var'=>'storage:bookmarks+notify'}),
]);
my $cap = DJabberd::Caps->new($dinfo->children_elements);
my $prs = DJabberd::Presence->available(from=>DJabberd::JID->new("$her/test"));
$prs->push_child(
    DJabberd::XMLElement->new('http://jabber.org/protocol/caps','c',
	{
	    xmlns=>'http://jabber.org/protocol/caps',
	    '{}node'=>'pep-test-03',
	    '{}hash'=>'sha256',
	    '{}ver'=>$cap->digest('sha256'),
	}
    )
);
$prs->set_to($my);
$prs->set_connection($fc);
$dtest = sub {
    my ($iq) = @_;
    if($iq->element_name eq 'iq' && $iq->signature eq 'get-{http://jabber.org/protocol/disco#info}query') {
	my $res = $iq->make_response;
	$res->push_child($dinfo->clone);
	$res->first_element->set_attr('{}node'=>$iq->first_element->attr('{}node'));
	$DJabberd::Plugin::PEP::logger->debug("Responding to disco with: ".$res->as_xml);
	$fc->push_s2s($res);
    } elsif($iq->element eq '{jabber:client}message') {
	$pepevt->($iq);
	ok(!(grep{$_->element eq '{http://jabber.org/protocol/address}addresses'}$iq->children_elements), "No addressing");
    } else {
	fail("Unexpected stanza");
	diag($iq->element.' '.($iq->can('signature') ? $iq->signature : $iq->as_xml));
    }
};
$stest = $nop;
$fc->push_s2s($prs);

# Create default [presence] access node
use MIME::Base64;
use Digest::SHA;
my $ava_b64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z/C/HgAGgwJ/lK3Q6wAAAABJRU5ErkJggg==';
my $ava_bin = MIME::Base64::decode($ava_b64);
my $ava_sha = Digest::SHA::sha1_hex($ava_bin);
my $ava_mdx = DJabberd::XMLElement->new('urn:xmpp:avatar:metadata','metadata',{xmlns=>'urn:xmpp:avatar:metadata'},[
	DJabberd::XMLElement->new(undef,'info',{
	    '{}id' => $ava_sha,
	    '{}type' => 'image/png',
	    '{}width' => 1,
	    '{}height' => 1,
	},[]),
    ]);
$item->set_raw();
$item->push_child($ava_mdx);
$item->set_attr('{}id' => $ava_sha);
$psp->set_attr('{}node' => 'urn:xmpp:avatar:metadata');
# fail if event was received
$dtest = sub {
    my ($e) = @_;
    if($e->to eq $prs->from) {
	fail('Thou shalt not pass');
    } else {
	fail("Actually nothing shalt pass: ".$e->as_xml);
    }
};
# but make sure our own pops up
$stest = $pepevt;
$fc->push_c2s($iq);
$item->remove_child($ava_mdx);

# Let's send directed presence again and make sure we still don't have event
# ignore sent presence
$stest = $nop;
$fc->push_s2s($prs);
# add her to the roster with subscription from
my $sub = DJabberd::Subscription->new();
my $ri = DJabberd::RosterItem->new( jid => $her, subscription => $sub);
$sub->set_from(1);

$vhost->run_hook_chain(phase   => "RosterSetItem",
		       args    => [ $fc->bound_jid, $ri ],
		       methods => {
			   done => sub {},
		       },
		   );
# Roster events are async, ensure the event was received
$dtest = sub {
    my ($e) = @_;
    $pepevt->($e);
    ok((grep{$_->element eq '{http://jabber.org/protocol/address}addresses'}$e->children_elements), "Has addressing");
};
diag("Pushing timers to process roster events");
Danga::Socket::RunTimers();

##
# Create private [whitelist] access node
my $bkm = DJabberd::XMLElement->new('storage:bookmarks','storage',{xmlns=>'storage:bookmarks'},[
    DJabberd::XMLElement->new(undef,'conference',{
	    '{}name' => 'The Play&apos;s the Thing',
	    '{}autojoin' => 'true',
	    '{}jid' => 'theplay@conference.shakespeare.lit'
	},[
	    DJabberd::XMLElement->new(undef,'nick',{},[],"JC")
	])
    ]);
$frm->{fields}->{'pubsub#access_model'}->{value}->[0] = 'whitelist';
$xfr = $frm->as_element;
$pbo->push_child($xfr);
$item->set_attr('{}id' => 'current');
$item->push_child($bkm);
$psp->set_attr('{}node' => 'storage:bookmarks');
$psq->push_child($pbo);
$dtest = sub {
    my ($e) = @_;
    fail("We don't expect anything: ".$e->as_xml);
};
$stest = sub {
    my ($e) = @_;
    $pepevt->($e);
};
$fc->push_c2s($iq);
$psq->remove_child($psp);
$psq->remove_child($pbo);

##
# Try to request bookmarks explicitly from trusted party
my $psi = DJabberd::XMLElement->new(undef, 'items', { '{}node' => 'storage:bookmarks' }, []);
$psq->push_child($psi);
$iq->set_attr('{}type'=>'get');
$iq->set_from($ri->jid);
$ecod = 403;
$dtest = sub {
    my ($e) = @_;
    $ecodok->($e->innards_as_xml);
};
$fc->push_s2s($iq);

##
# Repeat the query but now from own resource
$iq->set_from("$my/test2");
$dtest = sub {
    my ($e) = @_;
    ok($e->type eq 'result', 'Is result');
    if($e->first_element && $e->first_element->element_name eq 'pubsub') {
	my $p = $e->first_element;
	if($p->first_element && $p->first_element->element_name eq 'items') {
	    my $i = $p->first_element;
	    if($i->first_element && $i->first_element->element_name eq 'item') {
		like($i->first_element->innards_as_xml, qr{<storage xmlns=["']storage:bookmarks["']>}, "Has bookmark");
		return;
	    } else {
		fail("Unexpected content:  ".$i->innards_as_xml);
		return;
	    }
	}
    }
    fail("Unexpected response: ".$e->innards_as_xml);
};
$fc->push_c2s($iq);
$iq->remove_child($psq);

##
# We have now some nodes with all different pams, let's re-disco'm all to check permissions
my $dsq = DJabberd::XMLElement->new('http://jabber.org/protocol/disco#items', 'query', {xmlns=>'http://jabber.org/protocol/disco#items'}, []);
$iq->push_child($dsq);
$iq->set_attr('{}type'=>'get');
$iq->set_from("$her/blah");
$wtest = sub {
    my ($e) = @_;
    $res_ok->($e);
    like($e, qr{node=['"]urn:xmpp:omemo:1:devices["']}, "Has node devices") or diag($e);
    like($e, qr{node=['"]storage:bookmarks["']}, "Has node bookmarks") or diag($e);
    like($e, qr{node=['"]urn:xmpp:avatar:metadata["']}, "Has node metadata") or diag($e);
};
$dtest = sub {
    my ($e) = @_;
    ok($e->type eq 'result' && $e->innards_as_xml, 'Has results') or diag($e->as_xml);
    like($e->innards_as_xml, qr{node=['"]urn:xmpp:omemo:1:devices["']}, "Has node devices") or diag($e->innards_as_xml);
    like($e->innards_as_xml, qr{node=['"]urn:xmpp:avatar:metadata["']}, "Has node metadata") or diag($e->innards_as_xml);
    fail('Has node bookamrks: '.$e->innards_as_xml) if($e->innards_as_xml =~ qr{node=['"]storage:bookmarks["']});
};
$fc->push_c2s($iq);
$fc->{srv} = 1;
$fc->push_s2s($iq);
$iq->set_from("a\@b/c");
$dtest = sub {
    my ($e) = @_;
    ok($e->type eq 'result' && $e->innards_as_xml, 'Has results') or diag($e->as_xml);
    like($e->innards_as_xml, qr{node=['"]urn:xmpp:omemo:1:devices["']}, "Has node devices") or diag($e->innards_as_xml);
    fail('Has node bookamrks: '.$e->innards_as_xml) if($e->innards_as_xml =~ qr{node=['"]storage:bookmarks["']});
    fail('Has node metadata: '.$e->innards_as_xml) if($e->innards_as_xml =~ qr{node=['"]urn:xmpp:avatar:metadata["']});
};
$fc->push_s2s($iq);

package FakeCon;

sub new {
    bless { vh=>$_[1], jid=>$_[2], wr=>$_[3], sr=>$_[4], ss=>$_[5],
	xl=>DJabberd::Log->get_logger('FakeCon::XML'), in_stream => 1, srv => 0}, $_[0];
}

sub is_server { $_[0]->{srv} }
sub is_available { 1 }
sub vhost { $_[0]->{vh} }
sub bound_jid { $_[0]->{jid} }
sub xmllog { $_[0]->{xl} }
sub log_outgoing_data { $_[0]->{xl}->debug($_[1]) }
# Invoked by IQ response on C2S
sub write { $_[0]->{wr}->(@_) }
# Also invoked by IQ sometimes
sub on_stanza_received { $_[0]->{sr}->($_[1]) }
# Invoked by Delivery::Local (messages, presence, responses)
sub send_stanza { $_[0]->{ss}->($_[1]) }

sub push_c2s {
    my ($self, $stanza) = @_;
    $self->{vh}->hook_chain_fast('switch_incoming_client', [ $stanza],
	{
	    process => sub { $stanza->process($self) },
	    deliver => sub { $stanza->deliver($self) },
	},
	sub { $stanza->on_recv_from_client($self) });
}
sub push_s2s {
    my ($self, $stanza) = @_;
    $self->{vh}->hook_chain_fast('switch_incoming_server', [ $stanza],
	{
	    process => sub { $stanza->process($self) },
	    deliver => sub { $stanza->deliver($self) },
	},
	sub { $stanza->on_recv_from_server($self) });
}
