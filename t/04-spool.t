#!/usr/bin/perl
use strict;
use Test::More tests => 35;

use DJabberd;
DJabberd::Log::set_logger("main");
use DJabberd::VHost;
use DJabberd::Authen::AllowedUsers;
use DJabberd::Authen::StaticPassword;
use DJabberd::RosterStorage::InMemoryOnly;

use_ok("DJabberd::Plugin::PEP::Spool");

my $domain = "example.com";
my $dother = "example.org";

my $pep = DJabberd::Plugin::PEP::Spool->new();
File::Path::remove_tree('/tmp/_pep_test_');
$pep->set_config_spool_dir('/tmp/_pep_test_');
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

my $test;
my $psq = DJabberd::XMLElement->new('http://jabber.org/protocol/pubsub', 'pubsub', { xmlns => 'http://jabber.org/protocol/pubsub' });
my $iq = DJabberd::IQ->new('jabber:client', 'iq',
    {
	xmlns=> 'jabber:client',
	'{}type' => 'get',
	'{}from' => $her,
	'{}to' => $my,
	'{}id' => 'iq1',
    },
    [
	$psq,
    ]);
my $fc = FakeCon->new($vhost, DJabberd::JID->new($my), sub { $test->(${$_[1]}) });
$iq->set_connection($fc);
$vhost->register_hook("deliver", sub {
    my ($v, $cb, $stanza) = @_;
    $test->($stanza->as_xml);
    $cb->delivered();
}, 'DJabberd::Delivery::Local'); # Cheat to intercept S2S delivery

# Smoke test: get a 405 query error
$ecod=400;
$test = $ecodok;
$fc->push_s2s($iq);

# Smoke test: get a 403 access error
my $psi = DJabberd::XMLElement->new(undef, 'items', { '{}node' => 'urn:xmpp:omemo:1:devices' }, []);
$psq->push_child($psi);
$ecod=403;
$fc->push_s2s($iq);

# Smoke test: get a 404 error
$iq->set_from($my);
$ecod=404;
$fc->push_c2s($iq);

# Publish test
$iq->set_attr('{}type' => 'set');
$psq->remove_child($psi);
my $psp = DJabberd::XMLElement->new(undef, 'publish', { '{}node' => 'urn:xmpp:omemo:1:devices' }, []);
my $item = DJabberd::XMLElement->new(undef, 'item', { '{}id' => 'current' }, []);
my $devs = DJabberd::XMLElement->new('urn:xmpp:omemo:1', 'devices', {xmlns=>'urn:xmpp:omemo:1'}, [
    DJabberd::XMLElement->new(undef, 'device', {'{}id'=>'10', '{}label' => 'My Precious'},[])
]);
$item->push_child($devs);
$psp->push_child($item);
$psq->push_child($psp);
$test = $res_ok;
$fc->push_c2s($iq);
$psq->remove_child($psp);

# Retrieve test
$psq->push_child($psi);
$iq->set_attr('{}type'=>'get');
$test = sub {
    my ($res) = @_;
    $res_ok->($res);
    like($res, qr/label=['"](My Precious)["']/, "Has item payload");
};
$fc->push_c2s($iq);
$iq->remove_child($psq);

# Purge test
my $pso = DJabberd::XMLElement->new('http://jabber.org/protocol/pubsub#owner', 'pubsub', { xmlns => 'http://jabber.org/protocol/pubsub#owner' });
my $prg = DJabberd::XMLElement->new(undef, 'purge', { '{}node' => 'urn:xmpp:omemo:1:devices' }, []);
$pso->push_child($prg);
$iq->push_child($pso);
$iq->set_attr('{}type'=>'set');
$test = $res_ok;
$fc->push_c2s($iq);
$iq->remove_child($pso);

# make sure it's done
$iq->push_child($psq);
$iq->set_attr('{}type'=>'get');
$test = sub {
    my ($res) = @_;
    $res_ok->($res);
    ok($res =~ /<items node='urn:xmpp:omemo:1:devices'\/>/m, "Empty node");
};
$fc->push_c2s($iq);
$iq->remove_child($psq);

# Delete test
$prg->{element} = 'delete'; # enough of those elements
$iq->push_child($pso);
$iq->set_attr('{}type'=>'set');
$test = $res_ok;
$fc->push_c2s($iq);
$iq->remove_child($pso);

# make sure it's not there
$iq->push_child($psq);
$iq->set_attr('{}type'=>'get');
$test = $ecodok;
$ecod=404; 
$fc->push_c2s($iq);

# Publish with publish options (auto-create + auto-configure)
$psq->remove_child($psi);
$psq->push_child($psp);
my $pbo = DJabberd::XMLElement->new(undef, 'publish-options', {}, []);
my $frm = DJabberd::Form->new('submit', [
	{var=>'FORM_TYPE', value=>['http://jabber.org/protocol/pubsub#publish-options'], type=>'hidden'},
	{var=>'pubsub#access_model', value=>['open']},
    ]);
my $xfr = $frm->as_element;
$pbo->push_child($xfr);
$psq->push_child($pbo);
$iq->set_attr('{}type'=>'set');
$test = $res_ok;
$fc->push_c2s($iq);
$psq->remove_child($psp);
$psq->remove_child($pbo);

# Open-access retrieve test
$iq->set_from($her);
$iq->set_attr('{}type'=>'get');
$psq->push_child($psi);
$test = sub {
    my ($res) = @_;
    $res_ok->($res);
    like($res, qr/label=['"](My Precious)["']/, "Has item payload");
};
$fc->push_s2s($iq);
$psq->remove_child($psi);

# Failed pre-conditions publish test
$iq->set_from($my);
$iq->set_attr('{}type'=>'set');
$psq->push_child($psp);
$pbo->remove_child($xfr);
# FIXME: Hijack the form, need to do it properly
$frm->{fields}{'pubsub#max_items'}={value=>[10]};
push(@{ $frm->{order} },'pubsub#max_items');
$xfr = $frm->as_element;
$pbo->push_child($xfr);
$psq->push_child($pbo);
$test = sub {
    my ($res) = @_;
    $err_ok->($res);
    like($res, qr/<error\s+type=['"]cancel['"]><conflict\s+/, "Causes Conflict");
};
$fc->push_c2s($iq);
$iq->remove_child($psq);
$pbo->remove_child($xfr);

# check what have we configured then
$pso->remove_child($prg);
my $cfg = DJabberd::XMLElement->new(undef,'configure',{'{}node'=>$psp->attr('{}node')},[]);
$pso->push_child($cfg);
$iq->push_child($pso);
$iq->set_attr('{}type'=>'get');
$test = sub {
    my ($res) = @_;
    $res_ok->($res);
    like($res, qr/<field[^>]+var=['"]pubsub#access_model["'][^>]*>.*<value>open<\/value>/, "PAM is open");
    like($res, qr/<field[^>]+var=['"]pubsub#max_items["'][^>]*>.*<value>1<\/value>/, "Default max is 1");
};
$fc->push_c2s($iq);

# apply new config
$iq->set_attr('{}type' => 'set');
# multi-items does not work without persistent items, sorry
$frm->{fields}{'pubsub#persist_items'}={value=>[1]};
push(@{ $frm->{order} }, 'pubsub#persist_items');
$frm->{fields}->{FORM_TYPE}->{value}->[0] = 'http://jabber.org/protocol/pubsub#node_config';
$xfr = $frm->as_element or diag($frm->as_xml);
$cfg->push_child($xfr);
$test = $res_ok;
$fc->push_c2s($iq);
$iq->remove_child($pso);
$cfg->remove_child($xfr);

# repeat precondition test - add another item
$devs->first_element->set_attr('{}id' => 11);
$devs->first_element->set_attr('{}label' => 'My Preciouser');
$item->set_attr('{}id' => 'currentier');
$frm->{fields}->{FORM_TYPE}->{value}->[0] = 'http://jabber.org/protocol/pubsub#publish-options';
$xfr = $frm->as_element;
$pbo->push_child($xfr);
$iq->push_child($psq);
$fc->push_c2s($iq);
$psq->remove_child($psp);
$psq->remove_child($pbo);

# retrieve all items - should be two items
$psq->push_child($psi);
$iq->set_attr('{}type' => 'get');
$test = sub {
    my ($res) = @_;
    $DJabberd::Plugin::PEP::logger->debug($res);
    $res_ok->($res);
    like($res, qr{<item\s+id=['"]current['"]>}, "Has current item");
    like($res, qr{<item\s+id=['"]currentier['"]>}, "Has currentier item");
};
$fc->push_c2s($iq);

# retrieve single item: latest (cuurentier)
$psi->set_attr('{}max_items' => 1);
$test = sub {
    my ($res) = @_;
    $DJabberd::Plugin::PEP::logger->debug($res);
    $res_ok->($res);
    like($res, qr{<item\s+id=['"]currentier['"]>}, "Has currentier item");
};
$fc->push_c2s($iq);
$psi->set_attr('{}max_items' => undef);

# retrieve single item: by id (current)
$psi->push_child(DJabberd::XMLElement->new(undef, 'item', {'{}id'=>'current'},[]));
$test = sub {
    my ($res) = @_;
    $DJabberd::Plugin::PEP::logger->debug($res);
    $res_ok->($res);
    like($res, qr{<item\s+id=['"]current['"]>}, "Has current item");
};
$fc->push_c2s($iq);

######
# create a new pep instance and ensure it restored the state
my $pep2 = DJabberd::Plugin::PEP::Spool->new();
$pep2->set_config_spool_dir('/tmp/_pep_test_');
$pep2->finalize();
$pep2->{vhost} = $vhost;
$pep2->despool();

ok($pep2->get_pub($fc->bound_jid), "Has publisher");
ok($pep2->get_pub($fc->bound_jid, $psi->attr('{}node')), "Has node");
ok($pep2->get_pub_last($fc->bound_jid, $psi->attr('{}node'), undef, 1), "Has last item");
ok($pep2->get_pub_last($fc->bound_jid, $psi->attr('{}node'), undef, 1)->{id} eq 'currentier', "Which is currentier");
ok($pep2->get_pub_last($fc->bound_jid, $psi->attr('{}node'), 'current'), "Has older item");
like($pep2->get_pub_last($fc->bound_jid, $psi->attr('{}node'), 'current')->{data}, qr{label=["']My Precious['"]}, "Which is Precious");

package FakeCon;

sub new {
    bless { vh=>$_[1], jid=>$_[2], wr=>$_[3], xl=>DJabberd::Log->get_logger('FakeCon::XML')}, $_[0];
}

sub is_server { 0 }
sub vhost { $_[0]->{vh} }
sub bound_jid { $_[0]->{jid} }
sub xmllog { $_[0]->{xl} }
sub write { $_[0]->{wr}->(@_) }

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
