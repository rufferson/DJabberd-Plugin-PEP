package DJabberd::Plugin::PEP;
# vim: sts=4 ai:
use warnings;
use strict;
use base 'DJabberd::Plugin';
use DJabberd::Delivery::OfflineStorage;
use Digest::SHA;

use constant PUBSUBNS => 'http://jabber.org/protocol/pubsub';
use constant EXADDRNS => 'http://jabber.org/protocol/address';

our $logger = DJabberd::Log->get_logger();

=head1 NAME

DJabberd::Plugin::PEP - Implements XEP-0163 Personal Eventing Protocol

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

Implements XEP-0163 Personal Eventing Protocol (PEP) - a part of XMPP Advanced Server compliance [2010+].

    <VHost mydomain.com>
	<Plugin DJabberd::Plugin::PEP />
    </VHost>

=cut

=head2 register($self, $vhost)

Register the vhost with the module.

It sets PEP service feature as well as PEP service node, and registers hooks on c2s/s2s connections to
intercept PEP IQs, disco result IQs and Presence stanzas. Additionally it adds ConnectionClosing and
PresenceUnavailable hooks to remove explicit subscriptions (to full JID).

Supported XEP-0060 features implemented here are:
	'publish',
	'auto-create',
	'config-node',
	'purge-nodes',
	'delete-nodes',
	'auto-subscribe',
	'last-published',
	'retrieve-items',
	'publish-options',
	'access-presence',
	'presence-subscribe',
	'presence-notifications',
	'filtered-notifications',

See L<PERSISTENCE> for notes on non-volatile last-published implementation.

=cut

our @pubsub_features = (
	'publish',
	'auto-create',
	'config-node',
	'purge-nodes',
	'delete-nodes',
	'auto-subscribe',
	'last-published',
	'retrieve-items',
	'publish-options',
	'access-presence',
	'presence-subscribe',
	'presence-notifications',
	'filtered-notifications',
);

use constant DEF_CFG => {
    pam => 'presence',
    max => 1,
    deliver_notifications => 1,
    last => 'on_sub_and_presence',
    persist_items => 0,
    notification_type => 'headline',
    deliver_payloads => 1,
};

##
# mode explicit | implicit | loose
# explicit is not implemented yet
# implicit is the default (auto-subscribe)
# loose is the same except treat old 0115 presence as non-0115 - no disco, no filtering
sub set_config_mode {
    $_[0]->{sub_mode} = $_[1];
}

sub finalize {
    my $self = shift;
    $self->{sub_mode} ||= 'implicit';
    return $self->SUPER::finalize(@_);
}

sub register {
    my ($self,$vhost) = @_;
    my $manage_cb = sub {
	my ($vh, $cb, $iq) = @_;
	if($iq->isa("DJabberd::IQ")) {
	    my $sig = $iq->signature;
	    if((!$iq->to or ($iq->from && $iq->to eq $iq->from) or $iq->to eq $vh->name or $iq->to eq $iq->connection->bound_jid->as_bare_string)
		    and ($sig eq 'set-{'.PUBSUBNS.'}pubsub' or $sig eq 'set-{'.PUBSUBNS.'#owner}pubsub'))
	    {
		# This is only for direct c2s
		$logger->debug("PEP Modify: ".$iq->as_xml);
		$self->set_pep($iq);
		$cb->stop_chain;
		return;
	    } elsif((!$iq->to or $iq->to eq $iq->connection->bound_jid->as_bare_string) && $sig eq 'get-{'.PUBSUBNS.'#owner}pubsub') {
		$logger->debug("PEP Query: ".$iq->as_xml);
		$self->get_pep($iq,$iq->connection->bound_jid);
		$cb->stop_chain;
		return;
	    } elsif($self->disco_result($iq,$iq->connection->bound_jid)) {
		return $cb->stop_chain;
	    } elsif((!$iq->to || $vh->handles_jid($iq->to_jid)) && $iq->signature eq 'get-{'.PUBSUBNS.'}pubsub') {
		$logger->debug("PEP Query: ".$iq->as_xml);
		$self->get_pep($iq,$iq->connection->bound_jid);
		$cb->stop_chain;
		return;
	    }
	} elsif($iq->isa("DJabberd::Presence")) {
	    # Presence registration/check
	    $self->handle_presence($iq);
	}
	$cb->decline;
    };
    my $handle_cb = sub {
	my ($vh, $cb, $iq) = @_;
	if($iq->isa("DJabberd::IQ") && $iq->to && $iq->from) {
	    if($self->disco_result($iq,$iq->from_jid)) {
		return $cb->stop_chain;
	    } elsif ($vh->handles_jid($iq->to_jid) && $iq->signature eq 'get-{'.PUBSUBNS.'}pubsub') {
		$logger->debug("PEP Query: ".$iq->as_xml);
		$self->get_pep($iq,$iq->from_jid);
		return $cb->stop_chain;
	    }
	} elsif($iq->isa("DJabberd::Presence")) {
	    # Presence registration/check
	    $self->handle_presence($iq);
	} elsif($iq->isa("DJabberd::Message") and $iq->to and $iq->to_jid->is_bare and $vh->handles_jid($iq->to_jid) and $iq->attr('{}type') eq 'error') {
	    return $cb->stop_chain if($self->handle_error($iq));
	}
	$cb->decline;
    };
    my $ipresnc_cb = sub {
	my ($vh, $cb, $c) = @_;
	my $sub = $self->get_sub($c->bound_jid);
	if($sub && ref($sub) eq 'HASH') {
	    # check for disco condition: sub is set, has a node and caps is set but is scalar
	    my $cap = $self->get_cap($sub->{node}) if($sub->{node});
	    $logger->debug("InitialPresence on C2S[".$c->bound_jid->as_string.']: '.($cap || 'undef').' '.($sub->{node} || 'undef'));
	    if($cap && !ref($cap)) {
		# XEP-0115 enabled client pending caps discovery
		$self->req_cap($c->bound_jid,$sub->{node});
	    } elsif(!$sub->{node} or @{$sub->{topics}}) {
		# non-caps client or caps cached already - pending subscription
		$self->subscribe($c->bound_jid);
	    }
	}
	$cb->decline;
    };
    my $cleanup_cb = sub {
	my ($vh, $cb, $c) = @_;
	return $self unless($vh);
	if($c && $c->isa('DJabberd::Connection::ClientIn') && $c->bound_jid) {
	    $self->del_subpub($c->bound_jid);
	} elsif($c && $c->isa('DJabberd::Presence') && $c->from && !$c->from_jid->is_bare && !$c->is_directed) {
	    $self->del_subpub($c->from_jid);
	}
	$cb->decline;
    };
    my $roster_cb = sub {
	my ($vh, $cb, $for, $ri) = @_;
	# Let us be quick here, roster is used frequently everywhere
	Danga::Socket->AddTimer(0, sub {
	    if(!$ri->subscription->sub_from) {
		$self->unsubscribe($for,$ri->jid);
	    } else {
		# We should convert any transient subscriptions into presence auto-sub
		$self->set_subpub($ri->jid->as_string, $for->as_bare_string);
		$logger->debug("Caching presence subscription for ".$ri->jid->as_string." to ".$for->as_bare_string.": ".$self->get_subpub($ri->jid->as_string, $for->as_bare_string));
		my @jids = $self->get_sub($ri->jid);
		for my$fjs(@jids) {
		    my $jid = DJabberd::JID->new($fjs);
		    my $sub = $self->get_sub($jid);
		    my $to = ($sub && $sub->{node}) ? [ @{$sub->{topics}} ] : undef;
		    $logger->debug("Subscribing ".$jid." to $for on ".join(',',($to ? @$to : 'undef')));
		    $self->subscribe_for($jid, $for, $to);
		    $self->del_temp_sub($jid);
		}
	    }
	    # TODO: Roster group subscription update
	});
    };
    $self->{vhost} = $vhost;
    Scalar::Util::weaken($self->{vhost});
    # Publisher/Owner could only be C2S. It also needs to catch presence and disco.
    $vhost->register_hook("switch_incoming_client",$manage_cb);
    # S2S is mainly for presence handler, also disco and bounce
    $vhost->register_hook("switch_incoming_server",$handle_cb);
    # Whlie we capture presence, we cannot do much until server process it
    $vhost->register_hook("OnInitialPresence",$ipresnc_cb);
    # Below two should clean up presence cache.
    $vhost->register_hook("ConnectionClosing",$cleanup_cb);
    $vhost->register_hook("AlterPresenceUnavailable",$cleanup_cb);
    # Roster hook should track subscription to presence to forcibely unsubscribe
    # contact for 'roster' or 'presence' node subscription type
    $vhost->register_hook("RosterSetItem", $roster_cb);
    $vhost->caps->add(DJabberd::Caps::Identity->new("pubsub","pep","djabberd"));
    foreach my $psf(@pubsub_features) {
	$vhost->caps->add(DJabberd::Caps::Feature->new(PUBSUBNS.'#'.$psf));
    }
    $vhost->register_hook("DiscoBare", sub {
	my ($vh,$cb,$iq,$disco,$bare,$from,$ri) = @_;
	if($disco eq 'info' && $ri && ref($ri) && $ri->subscription->{from}) {
	    return $cb->addFeatures(['pubsub','pep'],map{PUBSUBNS."#$_"}@pubsub_features);
	} elsif($disco eq 'items') {
	    if($ri && ref($ri) && $ri->subscription->{from}) {
		return $cb->addItems(map{[$bare->as_bare_string,$_]}$self->get_pub_nodes($bare->as_bare_string));
	    } else {
		# TODO: list explicit subscriptions for $from
	    }
	}
	$cb->decline;
    });
    $vhost->register_hook("GetPlugin", sub { $_[1]->set($self) if($_[2] eq __PACKAGE__) });
    $self->{id} = 0;
}

sub vh {
    return $_[0]->{vhost};
}

sub handle_presence {
    my $self = shift;
    my $pres = shift;
    my $type = $pres->attr('{}type') || 'available';
    my $jid = $pres->from_jid || $pres->connection->bound_jid;
    return unless($jid && (!$pres->to or $self->vh->handles_jid($pres->to_jid)));
    if($type eq 'available') {
	my ($nver,$cap);
	my ($c) = grep{ ref($_) && $_->element eq '{http://jabber.org/protocol/caps}c'} $pres->children;
	# filter muc presence, it's useless
	my ($x) = grep{ ref($_) && $_->element eq '{http://jabber.org/protocol/muc#user}x'} $pres->children;
	if(!$x && $c && ref($c) && $c->isa('DJabberd::XMLElement')) {
	    my $ver = $c->attr('{}ver');
	    my $node = $c->attr('{}node');
	    my $hash = $c->attr('{}hash');
	    if($ver && $node && $hash) {
		$nver = "$node#$ver";
		$cap = $self->get_cap($nver);
		# The presence came to our account, so we need to know its filters even if we have no publishers at the moment
		if(!$cap or !ref($cap)) {
		    $logger->debug("Presence with caps spotted. Preparing to discover $hash $nver from ".$jid->as_string);
		    # Just note down that we're missing this caps entry
		    $self->set_cap($nver,$hash) unless($cap);
		    # If we don't have presence subscription cached let's cache transient subscription for directed presence
		    # FIXME: could be a fresh start, when nothing is published (and hence cached) yet.
		    $self->set_temp_sub($jid, $pres->to_jid) if($pres->to && !$self->get_subpub($jid,$pres->to_jid));
		    # We cannot trigger disco as of yet on c2s because at this phase presence is not processed
		    if($pres->connection->is_server or $pres->connection->is_available) {
			$self->req_cap($jid,$nver);
		    } else {
			# so let's just set empty one to start building request
			$self->set_sub($jid,$nver);
		    }
		    return; # The rest will be done in disco iq result handler
		} elsif(!ref($cap)) {
		    return;
		}
	    } else {
		$logger->debug('Presence with relict caps spotted: '.$c->as_xml);
		# if caps are in the presence we're supposed to apply filters
		# however early xep-0115 versions (1.3) did not include hash
		return unless($self->{sub_mode} eq 'loose');
		# In loose mode we treat pre-1.4 caps as no-caps hence no filtering
	    }
	}
	# We're here either because we already have caps or contact does not provide them in the presence
	my $sub = $self->get_sub($jid);
	# So, if there's no subscription or new caps differ from current subscription - need to (re)subscribe
	if(!$sub
		or (!$sub->{node} && $nver)
		or ($sub->{node} && !$nver)
		or ($sub->{node} && $nver && $nver ne $sub->{node}))
	{
	    # Let's remember it either by calculating subscriptions or flagging empty one
	    if($cap) {
		$self->set_sub($jid,$nver,map{$_->bare}$cap->{caps}->get('feature'));
	    } else {
		$self->set_sub($jid);
	    }
	    $logger->debug("Presence spotted, preparing to subscribe user ".$jid->as_string." to PEP events");
	    # and subscribe now to all active PEP nodes according to caps and active publishers
	    # optionally providing old topics to unsubscribe from missing
	    $self->subscribe($jid,($sub && @{$sub->{topics}}))
		if($pres->connection->is_server or $pres->connection->is_available); # skip c2s for same reason
	}
    } elsif($type eq 'unavailable') {
	$self->del_subpub($jid);
	$self->unsubscribe($pres->to_jid, $jid) if($pres->to_jid);
    }
}

sub req_cap {
    my $self = shift;
    my $user = shift;
    my $node = shift;
    $logger->debug("Requesting caps of $node for ".$user->as_string);
    my $iq = DJabberd::IQ->new(undef, 'iq', { '{}from'=>$self->vh->name, '{}to'=>$user->as_string, '{}type'=>'get' }, [
	DJabberd::XMLElement->new('http://jabber.org/protocol/disco#info','query',{ xmlns=>'http://jabber.org/protocol/disco#info', '{}node'=>$node },[])
    ]);
    $iq->set_attr('{}id',$self->gen_id);
    $iq->deliver($self->vh);
}

sub gen_id {
    my ($self, $type) = @_;
    $type ||= 'iq';
    return "pep-$type-".(int(rand(100)) + 100*($self->{id}++));
}
sub our_id {
    my ($self, $id) = @_;
    return undef unless($id =~ /^pep-(?:event|iq)-(\d+)$/);
    return undef unless($1 < $self->{id}*100);
    return $id;
}

sub disco_result {
    my $self = shift;
    my $iq = shift;
    my $from = shift;
    if((!$iq->to or $iq->to eq $self->vh->name) && $iq->signature eq 'result-{http://jabber.org/protocol/disco#info}query') {
	# This might be response to our discovery.
	my $node = $iq->first_element->attr('{}node') || "";
	return 0 unless($self->our_id($iq->id)); # maybe it was some reply, but is not our id, skip it
	return 0 unless($node); # It wasn't a reply to our request after all, we're always asking for node
	my $cap = $self->get_cap($node);
	return 0 unless($cap && !ref($cap)); # The node is set but we don't have it cached. Must be not ours either
	$logger->info("Got disco result for ".$node." from ".$iq->from);
	my $caps = DJabberd::Caps->new($iq->first_element->children_elements);
	my $capdgst = $caps->digest($cap); # when disco requested cap is set to hash algo
	my ($nuri,$digest) = split('#',$node);
	if($digest ne $capdgst) {
	    $logger->error("Digest mismatch: wrong hashing function $cap? $digest vs $capdgst");
	    $node = "$nuri#$capdgst";
	}
	# store caps to the cache
	$self->set_cap($node,$caps);
	# If caps changed we may need to unsubscribe some
	my $old = $self->get_sub($from);
	my @old = @{$old->{topics}} if($old && ref($old) eq 'HASH' && $old->{node} && ref($old->{topics}) eq 'ARRAY');
	$self->set_sub($from,$node,map{$_->bare}$caps->get('feature'));
	$logger->debug("Pending caps received, making subscription for ".$from->as_string);
	$self->subscribe($from,@old);
	return 1;
    }
    return 0;
}

sub gen_conf {
    my ($self, $cfg, $type) = @_;
    return undef unless(ref $cfg);
    $type ||= 'form';
    my %fields = (
	type => {},
	title => {},
	subscribe => {type=>'boolean'},
	tempsub => {type=>'boolean'},
	last => {var=>'send_last_published_item', option=>[{value=>'never'},{value=>'on_sub'},{value=>'on_sub_and_presence'}]},
	roster_groups_allowed => {type=>'list-multi'},
	purge_offline => {type=>'boolean'},
	publish_model => {option=>[{value=>'publishers'},{value=>'subscribers'},{value=>'open'}]},
	presence_based_delivery => {type=>'boolean'},
	persist_items => {type=>'boolean'},
	notify_sub => {type=>'boolean'},
	notify_retract => {type=>'boolean'},
	notify_delete => {type=>'boolean'},
	notify_config => {type=>'boolean'},
	notification_type => {option=>[{value=>'headline'},{value=>'normal'}]},
	node_type => {option=>[{value=>'leaf'},{value=>'collection'}]},
	max_payload_size => {},
	language => {type=>'list-single'},
	itemreply => {option=>[{value=>'owner'},{value=>'publisher'}]},
	item_expire => {},
	description => {},
	deliver_payloads => {type=>'boolean'},
	deliver_notifications => {type=>'boolean'},
	dataform_xslt => {},
	contact => {type=>'jid-multi'},
	collection => {type=>'text-multi'},
	children_max => {},
	children => {type=>'text-multi'},
	children_association_whitelist => {type=>'jid-multi'},
	children_association_policy => {option=>[{value=>'all'},{value=>'owners'},{value=>'whitelist'}]},
	body_xslt => {},
	max => {var=>'max_items'},
	pam => {var=>'access_model', option=>[{value=>'presence'},{value=>'roster'},{value=>'open'},{value=>'whitelist'}]},
    );
    my $form = [ {var=>'FORM_TYPE', type=>'hidden', value=>[PUBSUBNS.'#node_config']} ];
    for my $opt (keys(%{ $cfg })) {
	my $field = $fields{$opt} or die("This option[$opt] does not belong here");
	$field->{var} = 'pubsub#'.($field->{var} || $opt);
	if($type eq 'form') {
	    $field->{type} ||= ($field->{option} ? 'list-single' : 'text-single');
	} else {
	    # strip extras from submission form
	    delete $field->{type};
	    delete $field->{label};
	    delete $field->{option};
	}
	$field->{value} = (ref($cfg->{$opt}) eq 'ARRAY' ? $cfg->{$opt} : [ $cfg->{$opt} ]);
	push(@$form, $field);
    }
    return DJabberd::Form->new($type, $form);
}
sub parse_conf {
    my ($self, $fo) = @_;
    return undef unless($fo);
    my @fields = (
	'type',
	'title',
	'subscribe',
	'tempsub',
	'send_last_published_item',
	'roster_groups_allowed',
	'purge_offline',
	'publish_model',
	'presence_based_delivery',
	'persist_items',
	'notify_sub',
	'notify_retract',
	'notify_delete',
	'notify_config',
	'notification_type',
	'node_type',
	'max_payload_size',
	'language',
	'itemreply',
	'item_expire',
	'description',
	'deliver_payloads',
	'deliver_notifications',
	'dataform_xslt',
	['contact'],
	['collection'],
	'children_max',
	['children'],
	['children_association_whitelist'],
	'children_association_policy',
	'body_xslt',
	{'max_items' => 'max'},
	{'access_model' => 'pam'},
    );
    my $fn;
    $fn = sub {
	my ($v) = @_;
	if(ref($v)) {
	    if(ref($v) eq 'HASH') {
		return [values(%$v)]->[0] if($#_);
		return 'pubsub#'.[keys(%$v)]->[0];
	    } elsif(ref($v) eq 'ARRAY') {
		return $fn->($v->[0]);
	    }
	} else {
	    return $#_ ? $v : "pubsub#$v";
	}
    };
    my $o = {};
    for my $field (@fields) {
	$o->{ $fn->($field,1) } = (ref($field) eq 'ARRAY' ? [ $fo->value( $fn->($field) ) ] : [ $fo->value($fn->($field)) ]->[0]) if($fo->value($fn->($field)));
    }
    return $o;
}

=head2 set_pep($self,$iq)
=cut
=head2 get_pep($self,$iq,$from)

The methods are used to publish (set) or retrieve (get) pubsub items.

The method is called as a handler for corresponding IQ of type get or set with
pubsub{xmlns}/items{node}/item{id}/... child elements.

Set is called only on c2s connection when client speaks directly to server (no
to or to equal to server jid). It extracts published item and calls L<publish>
method to actually publish the payload.

Get is called for both c2s and s2s connection handlers but it checks permission
which is granted by implicit or explicit subscription state.

Get does not extract C<from> attribute from IQ Stanza, rather it requires caller
to supply what it considers as a trusted C<< from >> Djabberd::JID object.

=cut

sub set_pep {
    my $self = shift;
    my $iq = shift;
    my $jid = $iq->connection->bound_jid;
    if($iq->signature eq 'set-{'.PUBSUBNS.'#owner}pubsub') {
	$logger->debug('PEP Owner ops: '.$iq->innards_as_xml);
	my $op = $iq->first_element->first_element;
	my $node = $op->attr('{}node');
	if($op->element_name eq 'delete') {
	    $logger->debug("Deleting node $node from ".$jid->as_bare_string);
	    $self->del_pub($jid, $node);
	    $iq->send_result;
	} elsif($op->element_name eq 'purge') {
	    # We cannot purge much, just last perhaps
	    $logger->debug("Purging node $node from ".$jid->as_bare_string);
	    $self->set_pub_last(undef,$jid,$node);
	    $iq->send_result;
	} elsif($op->element_name eq 'configure') {
	    return $iq->send_error("<error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'></error>")
		unless($op->first_element);
	    my $frm = DJabberd::Form->new($op->first_element);
	    return $iq->send_error("<error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'></error>")
		unless($frm && (($frm->type eq 'submit'  && $frm->form_type eq PUBSUBNS.'#node_config') || $frm->type eq 'cancel'));
	    if($frm->type eq 'submit') {
		$logger->debug("Parsing config for form: ".$frm->as_xml);
		my $cfg = $self->parse_conf($frm);
		return $iq->send_error("<error type='cancel'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'></error>")
		    unless($self->set_pub_cfg($jid, $node, $cfg));
	    }
	    $iq->send_result;
	} else {
	    $iq->send_error("<error type='cancel'><feature-not-implemented xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'></error>");
	}
	return;
    }
    my @kids = grep { ref($_) && $_->element_name eq 'publish' } $iq->first_element->children;
    if(!$#kids && $kids[0]->attr('{}node') && $kids[0]->first_element->element_name eq 'item') {
	my $item = $kids[0]->first_element;
	my $node = $kids[0]->attr('{}node');
	# Handle publish options for pre-conditions or auto-creation
	my ($opts) = grep { ref($_) && $_->element_name eq 'publish-options' } $iq->first_element->children;
	if($opts && $opts->first_element && $opts->first_element->element eq '{jabber:x:data}x') {
	    my $frm = DJabberd::Form->new($opts->first_element);
	    return $iq->send_reply('error', "<error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>")
		unless($frm->type eq'submit' && $frm->form_type eq PUBSUBNS.'#publish-options');
	    my $o = $self->parse_conf($frm);
	    return $iq->send_reply('error', "<error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>")
		unless($o);
	    $logger->debug("Processing publish-options on node $node for $jid");
	    my $cfg = $self->get_pub_cfg($jid, $node);
	    if(ref $cfg) {
		# Validate precodnitions
		for my $k (keys(%$o)) {
		    return $iq->send_reply('error', "<error type='cancel'><conflict xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>")
			unless(defined $cfg->{$k});
		    my $v = $cfg->{$k};
		    if(ref($v) eq 'ARRAY' && ref($o->{$k}) eq 'ARRAY') {
			# new opts should be at least subset of existing
			return $iq->send_reply('error', "<error type='cancel'><conflict xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>")
			    unless(map{my$pov=$_;return grep{$_ eq $pov}@$v}@{$o->{$k}});
		    } elsif(ref($v) eq 'ARRAY' || ref($o->{$k}) eq 'ARRAY') {
			# This must not happen as long as we use the same parser for the node config
			return $iq->send_reply('error', "<error type='cancel'><conflict xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>");
		    } else {
			return $iq->send_reply('error', "<error type='cancel'><conflict xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>")
			    unless($v eq $o->{$k});
		    }
		}
	    } else {
		# Pre-create node
		return $iq->send_error("<error type='modify'><not-acceptable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'></error>")
		    unless($self->set_pub($jid, $node) && $self->set_pub_cfg($jid, $node, $o));
	    }
	}
	$iq->send_result;
	$logger->debug("Publishing PEP events for ".$jid->as_bare_string);
	$item->replace_ns(PUBSUBNS); # strip pubsub ns from the item
	$self->publish($jid, $node, $item);
	return;
    }
    $iq->send_error("<error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'></error>");
}
##
# $from is always set by the caller
sub get_pep($$$) {
    my $self = shift;
    my $iq = shift;
    my $from = shift or die('But it must be set?!');
    my $what = $iq->first_element->first_element;
    unless($what && ref($what)) {
	$logger->error("GOT UNKNOWN PEP ".$iq->as_xml);
	my $err = $iq->make_error_response(400,'modify','bad-request');
	return $err->deliver($self->vh);
    }
    my $node = $what->attr('{}node');
    if($iq->signature eq 'get-{'.PUBSUBNS.'#owner}pubsub') {
	if($what->element_name eq 'configure' && $node) {
	    my $cfg = $self->get_pub_cfg($from, $node);
	    unless($cfg && ref($cfg)) {
		my $ie = $iq->make_error_response(404,'cancel','item-not-found');
		$logger->debug("Requested node does not exist: ".$ie->as_xml);
		$ie->deliver($self->vh);
		return;
	    }
	    my $res = $iq->clone;
	    $res->set_to($iq->from);
	    $res->set_from($iq->to);
	    $res->set_attr('{}type','result');
	    my $cfx = $res->first_element->first_element;
	    my $frm = $self->gen_conf($cfg);
	    $cfx->push_child($frm->as_element);
	    $logger->debug("Posting configuration form: ".$cfx->as_xml);
	    return $res->deliver($self->vh);
	}
    }
    # Retrieve items fom the node
    if($what->element_name eq 'items' && $node) {
	my $node = $what->attr('{}node');
	unless($self->check_perms($from, ($iq->to_jid || $from), $node)) {
	    my $err = $iq->make_error_response(403,'cancel','not-allowed');
	    return $err->deliver($self->vh);
	}
	unless($self->get_pub($iq->to_jid,$node)) {
	    my $ie = $iq->make_error_response(404,'cancel','item-not-found');
	    $logger->debug("Requested node does not exist: ".$ie->as_xml);
	    $ie->deliver($self->vh);
	    return;
	}
	my $max = $what->attr('{}max_items');
	my $id = $what->first_element->attr('{}id') if($what->first_element);
	# make_response removes kids, we want to preserve
	my $res = $iq->clone;
	$res->set_to($iq->from);
	$res->set_from($iq->to);
	$res->set_attr('{}type','result');
	my @items = $self->get_pub_last($iq->to_jid, $node, $id, $max);
	$res->first_element->set_raw();
	$res->first_element->push_child(wrap_item($node, \@items));
	$res->deliver($self->vh);
    } else {
	$logger->error("GOT UNKNOWN PEP ".$iq->as_xml);
	my $err = $iq->make_error_response(405,'cancel','not-allowed');
	return $err->deliver($self->vh);
    }
}

sub check_perms {
    my $self = shift;
    my $from = shift;
    my $user = shift;
    my $node = shift;
    # Check implied (own resource) subscription
    return 1 if($from->as_bare_string eq $user->as_bare_string);
    if ($node) {
	my $pub = $self->get_pub($user,$node);
	# If node doesn't exist it's not allowed as it may be created as whitelist
	return 0 unless($pub);
	# Check explicit (existing) subscription to the node
	return 1 if($pub->{$from->as_bare_string});
	## PAM checks (pubsub access model)
	my $cfg = $self->get_pub_cfg($user, $node);
	if($cfg->{pam} eq 'presence') {
	    # Check subscriber's publishers cache which flags whether
	    # autosubscription is allowed by presence 'from' or 'both'
	    return 1 if($self->get_subpub($from->as_bare_string,$user->as_bare_string));
	} elsif($cfg->{pam} eq 'open') {
	    # Open is always allowed
	    return 1;
	} elsif($cfg->{pam} eq 'roster') {
	    # TODO: check roster group membership
	} elsif($cfg->{pam} eq 'whitelist') {
	    # TODO: check affiliations
	}
    }
    # nope
    return 0;
}
=head2 handle_error($self, $stanza)

The method handles bounces from subscribed users.

When error comes from full jid with explicit subscription - the full jid is unsubscribed.
If however there's no explicit subscription - the bounce is ignored because it will disable
delivery for the account untill some other resource explicitly subscribes to it (with presence
and caps). Which may be good idea after all. This may change in the future.

=cut

sub handle_error {
    my $self = shift;
    my $stanza = shift;
    my $to = $stanza->to;
    my $from = $stanza->from_jid;
    # Validate origin
    if($from && !$from->is_bare && $self->our_id($stanza->attr('{}id'))) {
	# Passed entry sanity check, capture and handle if possible
	my ($err) = grep{$_->element_name eq 'error'}$stanza->children;
	if($err && $err->attr('{}type') eq 'cancel') {
	    my ($event) = grep{$_->element_name eq 'event'} $stanza->children;
	    if($event && $event->first_element->element_name eq 'items' && $event->first_element->attr('{}node')) {
		my $node = $event->first_element->attr('{}node');
		if($self->get_pub($stanza->to,$node,$from->as_bare_string,$from->as_string)) {
		    $logger->info("Error received from ".$from->as_string.", unsubscribing from ".$node);
		    $self->del_pub($stanza->to, $node, $from);
		    # Actually if it is err we need to remove entire subscription. Err is not generated for UBM
		    $self->del_sub($from);
		} else {
		    $logger->info("Error received from ".$from->as_string." for ".$node." on bare push, cannot unsubscribe bare");
		}
	    } else {
		$logger->info("Error received from ".$from->as_string." but error misses event body, cannot handle so ignoring it");
	    }
	} elsif($err) {
	    $logger->info("Error received from ".$from->as_string." however error is transient(".$err->attr('{}type').") so ignoring it");
	} else {
	    $logger->info("Error received from ".$from->as_string." however error descriptor is missing so ignoring it");
	}
	return 1;
    }
    return 0;
}

=head2 emit($self, $event, $to)

The method is used to send published event to subscribed users.

It adds sender and id attribute to the cloned stanza and delivers it via vhost.
=cut

sub emit {
    my ($self, $event, $to) = @_;
    if($event && ref($event) && UNIVERSAL::isa($event,'DJabberd::Stanza')) {
	my $e = $event->clone;
	$e->set_to($to);
	$e->set_attr('{}id',$self->gen_id('event'));
	# Strip extended addressing if we don't have presence subscription cached
	unless($e->to_jid->as_bare_string eq $e->from_jid->as_bare_string || $self->get_subpub($e->to_jid->as_bare_string, $e->from)) {
	    $logger->debug("Stripping addressing from ".$e->from." to $to: ".($self->get_subpub($e->to_jid->as_bare_string, $e->from)||'undef'));
	    my ($ea) = grep {$_->element eq '{'.EXADDRNS.'}addresses'} $e->children_elements;
	    $e->remove_child($ea) if($ea);
	}
	$logger->debug("Emitting PEP Event: ".$e->as_xml);
	$e->deliver($self->vh);
    }
}

=head2 publish($self,$user,$node,$item)

This method is used to push the event $item published by $user for topic $node to all subscribers.

$user is DJabberd::JID object. $node is a string representing pubsub NodeID. $item - a DJabberd::XMLElement object
which was part of the original publish IQ.

It pushes an Event (<message type='headline'><event><item/></event></message>) in three stages. First delivers
it to all $user's connected resources. Then it sends to all explicit subscriptions (known full JIDs). Finally it
broadcasts to the remaining roster items with both/from subscription state - similar to presence broadcast.

The Event (DJabberd::Message object) is stored as last event - to be delivered to accounts appearing online.

=cut

sub wrap_item {
    my ($node, $item, $type, $delay) = @_;
    Carp::confess("wrong input: $item") unless(!$item || ref $item eq 'HASH' || ref $item eq 'ARRAY');
    my $items = DJabberd::XMLElement->new(undef,'items',{'{}node'=>$node}, []);
    if(ref $item eq 'HASH') {
	$items->push_child(DJabberd::XMLElement->new(undef, 'item', {'{}id'=>$item->{id}},[],$item->{data}));
    } elsif(ref $item eq 'ARRAY') {
	for my$i(@{ $item }) {
	    next unless($i); # We may have undef returned and pushed to the array
	    $items->push_child(DJabberd::XMLElement->new(undef, 'item', {'{}id'=>$i->{id}},[],$i->{data}));
	}
    }
    return $items unless($type);
    return undef unless($item);
    return DJabberd::Message->new('jabber:client','message',
	    {
		'{}from' => $item->{user}->as_bare_string,
		'{}type' => $type,
	    },[
		DJabberd::XMLElement->new(EXADDRNS,'addresses',{ xmlns => EXADDRNS },[
		    DJabberd::XMLElement->new(undef,'address',
			{
			    '{}type'=>'replyto',
			    '{}jid' => $item->{user}->as_string},
			[]),
		]),
		DJabberd::XMLElement->new(PUBSUBNS.'#event','event',{xmlns=>PUBSUBNS.'#event'}, [ $items ]),
		( $delay ? DJabberd::Delivery::OfflineStorage::delay($item->{ts}) : ())
	    ]);
}

sub publish {
    my ($self,$user,$node,$data) = @_;
    $logger->debug("Publishing stuff: $node ".$data->as_xml);
    # Prepare item structure for use and storage
    my $item = {
	data => $data->innards_as_xml,
	node => $node,
	user => $user,
	ts => scalar time,
	id => $data->attr('{}id')
    };
    $item->{id} ||= Digest::SHA::sha256_base64($item->{data});
    # And store for later use (new contacts)
    $self->set_pub_last($item);
    # Prepare headline event message
    my $event = wrap_item($node, $item, 'headline');
    # All user's resources are implicitly subscribed to all PEP events disregarding their capabilities.
    foreach my$con($self->vh->find_conns_of_bare($user)) {
	$self->emit($event,$con->bound_jid);
    }
    # All explicit subscriptions
    my $pub = $self->get_pub($user,$node);
    # Now walk through known subscribers
    foreach my$bare(get_pub_nodes($pub)) {
	foreach my$full(keys(%{$pub->{$bare}})) {
	    next unless($pub->{$bare}->{$full}); # Negative subscription - filtered out
	    $self->emit($event,$full);
	}
    }
    my $cfg = $self->get_pub_cfg($user, $node);
    # Then try to figure something from Roster and Subs if Access Model is roster based
    $self->vh->get_roster($user,on_success=>sub {
	my $roster = shift;
	my @ris;
	if($cfg->{pam} eq 'presence') {
	    @ris = $roster->from_items;
	} elsif($cfg->{pam} eq 'roster') {
	    # TODO: build list of RosterItems for the group
	}
	foreach my$ri (@ris) {
	    # check and skip if we have explicit full subsriptions for this bare as [XEP-0163 4.3.2] orders
	    my $ps = $self->get_pub($user,$node,$ri->jid->as_string);
	    next if($ps && ref($ps) eq 'HASH' && values(%{$ps}));
	    # No valid explicit subscriptions, check if we can build one
	    # But first let's register publisher at subscriber's cache
	    $self->set_subpub($ri->jid->as_string, $user->as_bare_string);
	    my @jids = $self->get_sub($ri->jid);
	    # We may have presence data collected already, let see
	    if(@jids) {
		# We do indeed.
		foreach my$sjid(@jids) {
		    my $sub = $self->get_sub($ri->jid, $sjid);
		    my @topics = grep{$_ eq $node}@{$sub->{topics}};
		    if(!$sub->{node} || @topics) {
			# User doesn't have caps or is interested in node notify
			$logger->debug("Subscribing $sjid to $node and pushing event");
			$self->set_pub($user,$node,$ri->jid->as_string,$sjid);
			$self->emit($event,$sjid);
		    } else {
			# User sent caps and they don't contain this node
			$self->set_pub($user,$node,$ri->jid->as_string,$sjid,0);
			$logger->debug("User $sjid doesn't want to receive $node events");
		    }
		}
		next;
	    }
	    # If we have no presence cache - we're likely starting up, let's skip flooding till we get one
	    next unless($self->get_sub);
	    # No presence knowledge, push to the bare
	    $self->emit($event,$ri->jid->as_string);
	}
    }) if($cfg->{pam} eq 'presence' || $cfg->{pam} eq 'roster');
}

=head2 subscribe_to($self, $pub_jid, $node, $sub_jid)

Set user's explicit subscription and push last event from node to him

=cut

sub subscribe_to {
    my ($self, $pubj, $node, $user) = @_;
    return unless($self->get_pub($pubj,$node)); # node is not published by jid
    return if($self->get_pub($pubj,$node,$user)); # already subscribed here
    # Flag the full jid under bare as active for node of pubj
    $self->set_pub($pubj,$node,$user->as_bare_string,$user->as_string,1);
    # Once subscribed - last event should be pushed.
    $self->emit(wrap_item($node,$self->get_pub_last($pubj,$node,,1),'headline',1),$user);
}

=head2 unsubscribe($self, $bpub, $bsub)

This method supposed to be used when presence subscription between bare pub and
bare sub has changed AND corresponding info is reflected in the publisher's
roster. Hence this method must be called from RosterSetItem hook, not presence
subscription type stanza.

If called from presence - cache may go out-of-sync when following happens:
subscriber removes subscription (presence sent), all relationships removed,
publishers receives notification and looks at client. It's status changes
which pushes new event through PEP. PEP builds new relationship from Roster.

=cut

sub unsubscribe {
    my ($self, $pub, $sub) = @_;
    # Filter out subscriber's jid from all publisher's topics (pubsub nodes)
    foreach my$topic($self->get_pub_nodes($pub)) {
	$self->del_pub($pub,$topic,$sub);
    }
    # also remove publisher from subscriber's cache
    $self->set_subpub($sub,$pub,0);
    $self->del_temp_sub($sub,$pub);
}

=head2 subscribe_for($self, $user, $pub)

=cut

sub subscribe_for {
    my ($self, $user, $bpub, $new, $old) = @_;
    if(ref $new) {
	# Let's walk through user's interest list and subscribe to matching nodes
	foreach my$t(@$new) {
	    $self->subscribe_to($bpub,$t,$user);
	    delete $old->{$t};
	}
	$logger->debug("Unsubscribing ".$user->as_string." from ".join('. ',keys(%$old))) if($old && %$old);
	foreach my$t(keys(%$old)) {
	    # Unsubscribe remaining extra by setting explicit nosub
	    next unless($t && $self->get_pub($bpub,$t)); # node is not published
	    $self->set_pub($bpub,$t,$user->as_bare_string,$user->as_string,0);
	}
    } else {
	# unless we use explicit subscription mode
	return if($self->{sub_mode} eq 'explicit');
	# No interests - let's subscribe to all available
	foreach my$t($self->get_pub_nodes($bpub)) {
	    $self->subscribe_to($bpub,$t,$user);
	}
    }
}

=head2 subscribe($self, $user[, ($topic1, $topic2, ...)])

Subscribe $user to all publishers which are pushing events to $user for interested nodes.

Also for each subscribed node - push last event to the user.

$user should be DJabberd::JID object containing full JID.

Optional list of topics may contain existing (previous) list so that extra items
from that list will be unsubscribed. This is to support client's filtering refresh.

=cut

sub subscribe {
    my $self = shift;
    my DJabberd::JID $user = shift;
    # Subsription attempt, may come from either presence event (auto) or explicit subscription request
    $logger->debug("Subscribing user ".$user->as_string." to ".join(', ', $self->get_sub_nodes($user)));
    # Assuming prsence event - so iterate through roster and find all publishers with both/from presence
    my @pubs = $self->get_subpub($user->as_bare_string);
    # Also check XEP-0060 9.1.2 auto-sub presence-sharer case
    push(@pubs,keys(%{{$self->get_temp_sub($user)}}));
    return unless(@pubs); # no established or pending subscriptions
    my $sub = $self->get_sub($user);
    return if($sub && $sub->{node} && !@{$sub->{topics}}); # We don't need no notifications
    my @topics = @{$sub->{topics}} if($sub && ref($sub) eq 'HASH' && ref($sub->{topics}) eq 'ARRAY');
    my %old = map {($_ => 1)} grep @_ if @_;
    $logger->debug("User ".$user->as_string." doesn't mind getting PEP events: ".(@topics ? join(', ',@topics):'all'));
    foreach my$bpub(@pubs) {
	unless($self->get_pub($bpub)) {
	    $logger->error("Relationship corruption: publisher $bpub exists for subscriber ".$user->as_string." but is missing in publishers list, removing");
	    $self->set_subpub($user->as_bare_string,$bpub,0);
	    next;
	}
	$logger->debug('Subscribing '.$user->as_string." to $bpub`s PEP events");
	$self->subscribe_for($user, $bpub, (($sub && $sub->{node}) ? [@topics] : undef), { %old });
    }
}

=head2 get_cap($self,$node)
=cut
=head2 set_cap($self,$node,$caps)

These calls are used to fill/check Entity Capability [XEP-0115] cache. The caps are used for
C<filtered-notifications> pubsub feature [XEP-0060]. It's vital to fill subscriber's cache.
If caps entry is missing - PEP will explicitly request a service discovery [XEP-0030] for the
JID having Entity Caps [XEP-0115] digest (ver='') in its presence.

$node here is a XEP-0115 node, not pubsub node. This node is usually UserAgent URI.

There's special state of caps which should be temporary only: when presence is received with
caps digest (ver) but such caps digest is missing in the cache - the caps is set to the
scalar value of hash algorithm. This indicates that we're actively looking to obtain user caps
via disco#info. When dicovery is fired and result received it is replaced with actual value.
=cut

sub get_cap {
    my $self = shift;
    my $node = shift;
    return $self->{cap}->{$node} if(exists $self->{cap}->{$node});
    return undef;
}
sub set_cap {
    my $self = shift;
    my $node = shift;
    my $caps = shift;
    if($self->{cap}->{$node} and !ref($self->{cap}->{$node})) {
	$self->{cap}->{$node} = { hash => $self->{cap}->{$node}, caps => $caps};
    } else {
	$self->{cap}->{$node} = $caps;
    }
}
=head2 get_pub($self,$user,$node,$bare,$full)
=cut
=head2 set_pub($self,$user,$node,$bare,$full,$val)

This is publisher management. Allows to get/set any part of the (sub)tree. For details see L<INTERNALS>.

=over

=item $user

is DJabberd::JID object of the publisher (pubsub node).

=item $node

is string representing pubsub NodeID - that is a PEP topic, like C<http://jabber.org/protocol/tune>

=item $bare

is a string representing subscriber's bare JID. Should be set when we're aware about some of the
explicit states and caps (filters) of the subscribers. Otherwise PEP will push the events together
with presence stanzas.

=item $full

is a string representing subscriber's fully qualified JID for which we know entity caps and hence
nodes (topics) it's interested in ($node."+notify"). One may disable subscription though by setting
it explicitly to false (0 or "") with $val.

set call also returns objects while walking down the leaf while traversing arguments. So it could be
used as initalizator when autocreating nodes/subscriptions. One need to follow internal structure to
creeate it manually (see L<INTENRALS>).

=back
=cut

sub get_pub {
    my $self = shift;
    my $user = shift;
    my $bare = (ref($user))? $user->as_bare_string : $user;
    return undef unless($bare); # must be bare JID
    return undef unless(exists $self->{pub}->{$bare} && ref($self->{pub}->{$bare}) eq 'HASH');
    my $node = shift;
    return $self->{pub}->{$bare} unless($node);
    return undef unless(exists $self->{pub}->{$bare}->{$node} && ref($self->{pub}->{$bare}->{$node}) eq 'HASH');
    my ($bsub,$full) = @_;
    return $self->{pub}->{$bare}->{$node} unless($bsub);
    ($bsub, $full) = ($bsub->as_bare_string, $bsub->as_string) if(ref $bsub);
    $full = undef if($full && $bsub eq $full);
    return undef unless(exists $self->{pub}->{$bare}->{$node}->{$bsub} && ref($self->{pub}->{$bare}->{$node}->{$bsub}) eq 'HASH');
    return $self->{pub}->{$bare}->{$node}->{$bsub} unless($full);
    return undef unless(exists $self->{pub}->{$bare}->{$node}->{$bsub}->{$full});
    return $self->{pub}->{$bare}->{$node}->{$bsub}->{$full};
}
sub set_pub {
    my $self = shift;
    my $user = shift;
    my $node = shift;
    my $bsub = shift;
    my $full = shift;
    Carp::confess("Wrong jid param: $user") if(ref $user && !UNIVERSAL::isa($user, 'DJabberd::JID'));
    my $bare = (ref($user))? $user->as_bare_string : $user;
    return unless($bare); # must be bare JID
    return $self->{pub}->{$bare} = $node if($node && ref($node) eq 'HASH');
    $self->{pub}->{$bare} = {} unless($self->get_pub($user));
    return $self->{pub}->{$bare}->{$node} = $bsub if($bsub && ref($bsub) eq 'HASH');
    $self->{pub}->{$bare}->{$node} = {} unless($self->get_pub($user,$node));
    return $self->{pub}->{$bare}->{$node} unless($bsub);
    return $self->{pub}->{$bare}->{$node}->{$bsub} = $full if($full && ref($full) eq 'HASH');
    $self->{pub}->{$bare}->{$node}->{$bsub} = {} unless($self->get_pub($user,$node,$bsub));
    $self->{pub}->{$bare}->{$node}->{$bsub}->{$full} = shift;
}
sub del_pub {
    my ($self, $user, $node, $sub) = @_;
    my $pub = ref $user ? $user->as_bare_string : $user;
    return unless($user && $node);
    return delete $self->{pub}{$pub}{$node} unless($sub);
    if(!ref($sub) || $sub->is_bare) {
	delete $self->{pub}{$pub}{$node}{ (ref $sub ? $sub->as_bare_string : $sub) };
    } else {
	delete $self->{pub}{$pub}{$node}{$sub->as_bare_string}{$sub->as_string};
    }
}

sub set_pub_cfg($$$$) {
    my ($self, $jid, $node, $cfg) = @_;
    Carp::confess("Invalid input") unless(ref($jid) && $node && ref($cfg));
    my $pub = $self->get_pub($jid, $node);
    return undef unless(ref($pub) eq 'HASH');
    # strip defaults
    for my$k(keys(%{$cfg})) {
	delete $cfg->{$k} if($cfg->{$k} eq DEF_CFG->{$k});
    }
    return $pub->{'@cfg@'} = $cfg;
}
sub get_pub_cfg($$$) {
    my ($self, $jid, $node, $short) = @_;
    my $pub = $self->get_pub($jid, $node);
    return undef unless(ref($pub) eq 'HASH');
    if($short) {
	return $pub->{'@cfg@'} if(ref $pub->{'@cfg@'});
	return {};
    } else {
	my $ret = { %{ DEF_CFG() } };
	if(ref $pub->{'@cfg@'}) {
	    my @k = keys(%{ $pub->{'@cfg@'} });
	    @{$ret}{@k} = @{$pub->{'@cfg@'}}{@k};
	}
	return $ret;
    }
}

=head2 get_pub_last($self, $user, $node, $id, $max)
=cut
=head2 set_pub_last($self, $item, $user, $node, $id)

Fetches and sets last event published by the user to given pubsub node.

$event is a HASHREF object containing published item. See L<INTERNALS>
for details.

If C<$item> is C<undef> then it wipes (deletes, retracts, purges) the
content. If C<$id> is provided then single item is retracted, otherwise
entire node is purged.
=cut

sub get_pub_last {
    my ($self, $user, $node, $id, $max) = @_;
    my $pub = $self->get_pub($user,$node);
    return undef unless($pub && ref($pub) eq 'HASH' && exists $pub->{'@last@'});
    return $pub->{'@last@'};
}
sub set_pub_last {
    my ($self, $item, $user, $node, $id) = @_;
    Carp::confess("Wrong item: $item") if(ref $item && ref $item ne 'HASH');
    $user = $item->{user} if(ref $item && !$user);
    $node = $item->{node} if(ref $item && !$node);
    my $pub = $self->set_pub($user,$node);
    # asking to remove something when there's nothing here
    return if(!ref($item) && !ref($pub->{'@last@'}));
    # Asking to remove an item which is not here
    return if(!ref($item) && $id && $id ne $pub->{'@last@'}->{id});
    # either purge or set/retract last
    return $pub->{'@last@'} = $item;
}

=head2 get_pub_nodes($self, $user)

A method which returns all (auto-)created pubsub nodes for the given root
collector represented by bare JID.

Returns array of strings representing pubsub nodeID (namespaces)
=cut

sub get_pub_nodes {
    my ($self, $user) = @_;
    my $pub = ref($self) eq 'HASH' ? $self : $self->get_pub($user);
    return () unless($pub && ref($pub) eq 'HASH');
    return grep{$_ && $_ ne '@last@' && $_ ne '@cfg@' && ref($pub->{$_})} keys(%{$pub});
}
sub get_sub_nodes {
    my $self = shift;
    my $user = shift;
    return undef unless($user && ref($user) && UNIVERSAL::isa($user,'DJabberd::JID'));
    my $sub = $self->get_sub($user);
    return undef unless($sub && ref($sub) eq 'HASH');
    return @{$sub->{topics}};
}
=head2 get_sub($self,$user)
=cut
=head2 set_sub($self,$user,$node,(@list))

These calls are used to manage subscriber's state.

Subscriber's state is a hint, or presence/cap cache which indicates implicit
(presence based) subscription request. It's not used actively for publish or
delivery.  The state is set when user sends available presence (goes online)
with entity caps visible on PEP service.

PEP then resolves caps figuring C<+notify> topics and sets them in subscription
state. If later publisher goes online it will use the cached pre-set hints for
C<filtered-notifications> pubsub feature. Presence without notifications will
still register an entry in sub table, but empty caps entry means catch-all or
follow-the-presence.

The @list argument is representing list of features discovered from the client
(disco#info result's var list) - from DJabberd::Caps object received from
get_cap call.

When get_sub is called with no arguments - it returns all second level keys
representing full jids of contacts with known presence.
=cut

sub get_sub {
    my ($self, $user, $full) = @_;
    # return all online full jids captured from presence
    return grep{$_ ne 'pub'}map{keys(%{$_})}values(%{$self->{sub}}) unless($user);
    # return online full jids for this bare jid (string or object)
    my $bare = (ref($user) ? $user->as_bare_string : $user);
    $full = $user->as_string if(ref($user) && !$user->is_bare);
    return grep{$_ ne 'pub'}keys(%{$self->{sub}->{$user}}) unless($full);
    return $self->{sub}->{$bare}->{$full};
}
sub set_sub {
    my $self = shift;
    my $user = shift;
    my $node = shift;
    # Node#ver here is used to flag that empty subscription list means exactly
    # that - no interest expressed explicitly for this UserAgent/Caps
    my $sub = { node => $node, topics => []};
    foreach my$f(@_) {
	if($f =~ /^(.+)\+notify$/) {
	    push(@{$sub->{topics}},$1);
	}
    }
    $self->{sub}->{$user->as_bare_string} = { pub => {} }
	unless(ref($self->{sub}->{$user->as_bare_string}) eq 'HASH');
    $self->{sub}->{$user->as_bare_string}->{$user->as_string} = $sub;
}
sub del_sub {
    my ($self, $user) = @_;
    return undef unless(ref($user) && !$user->is_bare);
    return delete $self->{sub}{$user->as_bare_string}{$user->as_string};
}

=head2 get_subpub($self, $bsub[, $bpub])
=cut
=head2 set_subpub($self, $bsub, $bpub[, $val])

These calls are used to manage subscriber-to-publisher relationship.

Since subscribers can be remote users we cannot get their roster and resovle
their publishers. Iterating through all publishers and their rosters is tedious
work. Hence this fast lookup cache is built when publisher pushes the event to
the contact on the roster. In other words it is a reversed roster cache (of the
C<from> subscription types, contact C<$bsub> from user C<$bpub>).

$bsub and $bpub are strings representing bare jid of the subscriber and publisher.

When $val is provided and is 0 - set_subpub call will remove the relationship.
Otherwise - when it's not provided or is 1 - will set the relationship.

When presence or caps of the user received - get_subpub will be used to build
specific subscriptions to stop broadcasting events to bare jid and instead
push them to interested resources only.

For instance, C<if(get_subpub($contact,$user))> tells that B<$user> allows
autosubscription to his PEP events for the B<$contact> (due to current presence
subscription state or for any other reason).

And consequently C<$pep->set_subpub($contact,$user,0);> disables autosubsription
for B<$contact> to B<$user>'s PEP events.
=cut

sub get_subpub {
    my $self = shift;
    my $bsub = shift;
    return () unless(exists $self->{sub}->{$bsub} && ref($self->{sub}->{$bsub}) && exists $self->{sub}->{$bsub}->{pub});
    my $bpub = shift;
    return keys(%{$self->{sub}->{$bsub}->{pub}}) unless($bpub);
    return ((exists $self->{sub}->{$bsub}->{pub}->{$bpub})? $self->{sub}->{$bsub}->{pub}->{$bpub} : undef);
}
sub set_subpub {
    my $self = shift;
    my $bsub = shift;
    my $bpub = shift;
    $self->{sub}->{$bsub} = { pub => {} } unless(ref($self->{sub}->{$bsub}) eq 'HASH');
    return $self->{sub}->{$bsub}->{pub}->{$bpub} = ($_[0] || 1) if(!@_ or $_[0]); # implicit or explicit set
    return delete $self->{sub}->{$bsub}->{pub}->{$bpub}; # this was a removal call
}

=head2 del_pubsub()

The call intended to clean up the mess after previous two. And some others. The ultimate unsubscribe.

Actually it tries to remove all bi-directional references between publisher and subscriber but only to remove
explicit full jid subscription without touching global state. In other words - to reverse explicit subscription
relationship built on presence/caps reception. Hence it should be used in unavailable presence handler.
=cut

sub del_subpub {
    my $self = shift;
    my $user = shift;
    return unless($user && ref($user) && !$user->is_bare);
    my @pubs = (keys(%{$self->{sub}->{$user->as_bare_string}->{pub}}), keys(%{{$self->get_temp_sub($user)}}));
    $logger->debug("Removing all subscriptions for ".$user->as_string." from ".join(', ', @pubs));
    foreach my$p(@pubs) {
	my @nodes;
	if($self->{sub}->{$user->as_bare_string}->{$user->as_string}->{node}) {
	    @nodes = $self->get_sub_nodes($user);
	} else {
	    @nodes = $self->get_pub_nodes($p);
	}
	foreach my$n(@nodes) {
	    delete $self->{pub}->{$p}->{$n}->{$user->as_bare_string}->{$user->as_string}
		if(ref $self->{pub}->{$p}->{$n}->{$user->as_bare_string});
	}
	$self->del_temp_sub($user,$p);
    }
    $self->del_sub($user);
}

=head2 get_temp_sub($self, $sub[, $bpub])
=cut
=head2 set_temp_sub($self, $sub, $bpub[, $node1, ...])

Similar to the previous call this call is indicating subscriber-to-publisher
relationship, however unlike that one it represents relationship not based on
presence subscriptions but rather explicit subscription requests to specific
user (and maybe to specific node).

The subscription could be either IQ-based (XEP-0060 6.1.1) or directed-presence
based (XEP-0060 9.1.3)

The first argument (after $self) should be either DJabberd::JID object or a
string representing required subscriber's jid serialisation. If JID object is
passed to C<set> or C<get> calls it will be used to take its full form, 
C<as_string> which however may contain bare jid. Either way full and bare
relationships are different and you may need to call it twice to collect both.

The second argument is a JID object or string representing collection node
(which is bare JID of the publisher). If JID object is passed its
C<as_bare_string> serialisation form will be taken.

Returns hash with keys being requested publishers and values array ref of
requested nodes (for IQ) or undef (for directed presence).

=cut

sub set_temp_sub($$$@) {
    my ($self, $jid, $pub, @nodes) = @_;
    my $sub = ref($jid) ? $jid->as_string : $jid;
    $pub = $pub->as_bare_string if ref $pub;
    $self->{tmp}{$sub}{$pub} = (@nodes ? [ @nodes ] : undef);
}
sub get_temp_sub($$;$) {
    my ($self, $jid, $pub) = @_;
    $pub = $pub->as_bare_string if ref $pub;
    my $sub = ref($jid) ? $jid->as_string : $jid;
    if($pub) {
	my %ret = ( $pub => $self->{tmp}{$sub}{$pub} )
	    if(ref $self->{tmp}{$sub} && exists $self->{tmp}{$sub}{$pub});
	return %ret;
    }
    my %ret = %{ $self->{tmp}{$sub} } if(ref($self->{tmp}{$sub}));
    return %ret;
}
sub del_temp_sub($$;$$) {
    my ($self, $jid, $pub,$node) = @_;
    my $sub = ref($jid) ? $jid->as_string : $jid;
    $pub = $pub->as_bare_string if ref $pub;
    return delete $self->{tmp}{$sub} unless($pub);
    return delete $self->{tmp}{$sub}{$pub} unless($node);
    if(ref $self->{tmp}{$sub}{$pub}) {
	$self->{tmp}{$sub}{$pub} = [ grep{$_ ne $node}@{$self->{tmp}{$sub}{$pub}} ];
    }
}

=head1 PERSISTENCE

This implementation is memory-only last-only. That is - all pep events as well
as PEP nodes are volatile, PEP node is always autocreated and merely distributes
events in real-time, caching last published event only, which will be pushed to
subscriber on subscription (presence) event.

That last message will not survive server restart, that however should not be a
problem because client will re-connect and re-publish its tunes/nicks/moods/etc.

If such last event is required to be persistant - implementation should override
L<set_pub_last> and L<get_pub_last> calls, storing the event and calling SUPER.
Also would make sense adding C<persistent-items> feature to the list of supported
features (eg. push(@DJabberd::Plugin::PEP::pubsub_features,'persistent-items');).

Event retrieval is also supported, and will call C<get_pub_last> to fetch the
item[s]. However for that to work for anything but last item the non-volatile
implementation should store more items in C<set_pub_last> and retrieve more in
C<get_pub_last> calls. Later has optional parameters C<id> and C<max> which
are serving as selectors to retrieve specific items from storage.

The stored C<item> is a hashref with serialised item XML, NodeId, full JID of
the publisher and delivery timestamp (see L<INTERNALS>).

In addition to items persistent implementation would need to override two
methods - L<set_pub_cfg> and L<del_pub>. Former should call SUPER and save
config to the persistent storage. And the later will need to properly delete
pubsub node and then call SUPER to clear runtime state.

=cut

=head1 INTERNALS
=cut
=head2 Event flow

Publish -> send headlines to subscribed resources -> get roster -> walk through both/to resources -> push to bare jid -> store last event

Note: all publisher's (available) resources are implicitly subscribed (as presence is)

Presence received -> check digest (ver) -> invalidate subscription if differs -> if subscription missing request caps otherwise ignore

Caps received -> validate digest -> build subscriptions if missing -> walk through online publishers -> subscribe and push last

Bare JID disco#info received -> send static identity/features.

Bare JID disco#items received -> send published nodes (if subscribed)
=cut

=head2 Structs:

You don't normally need these structs as higher level calls (get/set_) should
cover general cases.

Capabilities:
$self->{cap}->{"<node>#<digest>"} = { hash => '(sha-1|sha-256|...), caps => DJabberd::Caps }

Publishers:
This is probably the most complex structure - as it's (supposedly) most frequently
used.  It's supposed to be fully managed through get/set_pub methods however. It
could be fully managed by those calls, up to setting/getting entire publisher's
tree.

 $self->{pub}->{'publisher_bare_jid'} = {
    'pubsub_node1' => {
	'@last@' => {
	    node => 'pubsub_node1',
	    data => 'xml_payload_inside_<item>_tags',
	    user => DJabberd::JID('publisher_full_jid'),
	    id => 'supplied_id_or_autogenerated_digest',
	    ts => time()
	},
	@cfg@ => {
	    option => value,
	    ...,
	},
	'subscriber1_bare_jid' => {
	    'subscriber1_full_jid1' => 1,
	    ...,
	    'subscriber1_full_jidX' => 1
	},
	...,
	'subscriberN_bare_jid> => {
	    'subscriberN_full_jid1' => 1,
	    ...,
	    'subscriberN_full_jidY' => 1
	},
    },
    ...,
    'pubsub_nodeZ' => {
	'@last@' => { ... },
	'@cfg@' => { ... },
	'subscriber1_bare_jid' => {
	    'subscriber1_full_jid1' => 1,
	    ...,
	},
	...,
    }
 }


Subscribers:
While local subscribers could be back-resolved from their roster, remote could not enjoy this service
hence need a back-reference to resolve and build their specific subscriptions. That's achieved by pub
node of the subscriber's sub tree. It's filled in by publisher when pushing to bare jid. PEP then can
use this tree to resolve publishers on reception of the disco#info or presence stanzas with caps. In
the essence it is a presence cache with caps (and topics) and backref to pubs which used this entry.

 $self->{sub}->{'subscriber_bare_jid'} =  {
    <subscriber_full_jid>} = {
	node => "<node>#<digest>,
	topics => [ <pubsub_node1>, ..., <pubsub_nodeN> ]
    }
    pub => {
	'publisher_bare_jid' => 1,
	...
    }
 }

Here "<node>#<digest>" are node and ver fields of XEP-0115 entity capabilities
<c> element.

To complete publishers struct for a bare_jid one needs bare_jid's Roster
<both and to> and Subscribers struct, where subscribers is built from Caps.

It could be filled in from the opposite end - having publisher's struct one can
append it using subscriber's Roster <both and from> and Caps.

C<Subscribers> is rather a filter/preferences list, we will broadcast to bare
jid the events unless we have explicit subscription with filters.

=cut
=head1 AUTHOR

Ruslan N. Marchenko, C<< <me at ruff.mobi> >>

=head1 COPYRIGHT & LICENSE

Copyright 2016 Ruslan N. Marchenko, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut
1;
