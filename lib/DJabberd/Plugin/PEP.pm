package DJabberd::Plugin::PEP;
# vim: sts=4 ai:
use warnings;
use strict;
use base 'DJabberd::Plugin';

use constant {
	PUBSUBNS => "http://jabber.org/protocol/pubsub",
};
use POSIX 'strftime';

our $logger = DJabberd::Log->get_logger();

=head1 NAME

DJabberd::Plugin::PEP - Implements XEP-0163 Personal Eventing Protocol

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

Implements XEP-0163 Personal Eventing Protocol (PEP) - a part of XMPP Advanced Server compliance [2010].

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
	'auto-subscribe',
	'last-published',
	'retrieve-items',
	'access-presence',
	'presence-subscribe',
	'presence-notifications',
	'filtered-notifications',

See L<PERSISTENCE> for notes on non-volatile last-published implementation.

=cut

our @pubsub_features = (
	'publish',
	'auto-create',
	'auto-subscribe',
	'last-published',
	'retrieve-items',
	'access-presence',
	'presence-subscribe',
	'presence-notifications',
	'filtered-notifications',
);

sub register {
    my ($self,$vhost) = @_;
    my $manage_cb = sub {
	my ($vh, $cb, $iq, $c) = @_;
	if($iq->isa("DJabberd::IQ")) {
	    if((!$iq->to or $iq->to eq $iq->from or $iq->to eq $vh->name) && $iq->signature eq 'set-{'.PUBSUBNS.'}pubsub') {
		# This is only for direct c2s
		$logger->debug("PEP Modify: ".$iq->as_xml);
		$self->set_pep($iq);
		$cb->stop_chain;
		return;
	    } elsif($self->disco_bare_jid($iq,$iq->connection->bound_jid)) {
		$cb->stop_chain;
		return;
	    } elsif ($iq->to && $vh->handles_jid($iq->to_jid) && $iq->signature eq 'get-{'.PUBSUBNS.'}pubsub') {
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
	    if($self->disco_bare_jid($iq,$iq->from_jid)) {
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
	if($c && $c->isa('DJabberd::Connection::ClientIn') && $c->bound_jid) {
	    $self->del_subpub($c->bound_jid);
	} elsif($c && $c->isa('DJabberd::Presence') && $c->from && !$c->from_jid->is_bare) {
	    $self->del_subpub($c->from_jid);
	}
	$cb->decline;
    };
    $self->{vhost} = $vhost;
    # Publisher/Owner could only be C2S. It also needs to catch presence and disco.
    $vhost->register_hook("switch_incoming_client",$manage_cb);
    # S2S is mainly for presence handler, also disco and bounce
    $vhost->register_hook("switch_incoming_server",$handle_cb);
    # Whlie we capture presence, we cannot do much until server process it
    $vhost->register_hook("OnInitialPresence",$ipresnc_cb);
    # Below two should clean up presence cache.
    $vhost->register_hook("ConnectionClosing",$cleanup_cb);
    $vhost->register_hook("AlterPresenceUnavailable",$cleanup_cb);
    # Roster hook should track subscription to presence to forcibely unsubscribe contact
    # TODO on update/delete hooks doing cleanup. Althoug presence should suffice.
    $vhost->caps->add(DJabberd::Caps::Identity->new("pubsub","pep","djabberd"));
    foreach my $psf(@pubsub_features) {
	$vhost->caps->add(DJabberd::Caps::Feature->new(PUBSUBNS.'#'.$psf));
    }
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
	if($c && ref($c) && $c->isa('DJabberd::XMLElement')) {
	    my $ver = $c->attr('{}ver');
	    my $node = $c->attr('{}node');
	    my $hash = $c->attr('{}hash');
	    if($ver && $node && $hash) {
		$nver = "$node#$ver";
		$cap = $self->get_cap($nver);
		# The presence came to our account, so we need to know its filters even if we have no publishers at the moment
		if(!$cap or !ref($cap) or !$cap->{caps}) {
		    $logger->debug("Presence with caps spotted, but caps missing. Preparing to discover $hash $nver from ".$jid->as_string);
		    # Just note down that we're missing this caps entry
		    $self->set_cap($nver,$hash);
		    # We cannot trigger disco as of yet on c2s because at this phase presence is not processed
		    if($pres->connection->is_server or $pres->connection->is_available) {
			$self->req_cap($jid,$nver);
		    } else {
			# so let's just set empty one to start building request
			$self->set_sub($jid,$nver);
		    }
		    return; # The rest will be done in disco iq result handler
		}
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
    }
}

sub req_cap {
    my $self = shift;
    my $user = shift;
    my $node = shift;
    $logger->debug("Requesting caps of $node for ".$user->as_string);
    my $iq = DJabberd::IQ->new('', 'iq', { '{}from'=>$self->vh->name, '{}to'=>$user->as_string, '{}type'=>'get' }, [
	DJabberd::XMLElement->new('','query',{ xmlns=>'http://jabber.org/protocol/disco#info', node=>$node },[])
    ]);
    $iq->set_attr('{}id','pep-iq-'.$self->{id}++);
    $iq->deliver($self->vh);
}

sub disco_bare_info {
    # This is static
    return (
	DJabberd::XMLElement->new('','identity',{category=>'pubsub', type=>'pep'},[]),
	DJabberd::XMLElement->new('','feature', {var=>'http://jabber.org/protocol/disco#info'},[]),
	DJabberd::XMLElement->new('','feature', {var=>'http://jabber.org/protocol/disco#items'},[]),
	map{DJabberd::XMLElement->new('','feature', {var=>PUBSUBNS.'#'.$_},[])}@pubsub_features
    );
}
sub disco_bare_items {
    my $self = shift;
    my $user = shift;
    my @ret;
    # List autocreated nodes
    foreach my$node ($self->get_pub_nodes($user)) {
	push(@ret,DJabberd::XMLElement->new('','item',{jid=>$user,node=>$node},[]));
    }
    return @ret;
}

sub disco_bare_jid {
    my $self = shift;
    my $iq = shift;
    my $from = shift;
    # if request goes to explicit bare jid of the local user
    if($iq->to && $iq->to_jid->is_bare && $iq->to ne $self->vh->name && $self->vh->handles_jid($iq->to_jid)) {
	# Handle explicit discovery of the user's bare jid - represent the user with PEP node.
	if($iq->signature eq 'get-{http://jabber.org/protocol/disco#info}query'
	  or $iq->signature eq 'get-{http://jabber.org/protocol/disco#items}query')
	{
	    unless($self->check_perms($from,$iq->to_jid)) {
		my $err = $iq->make_error_response(403,'cancel','not-allowed');
		return $err->deliver($self->vh);
	    }
	    my @stuffing;
	    if($iq->signature eq 'get-{http://jabber.org/protocol/disco#items}query') {
		@stuffing = $self->disco_bare_items($iq->to);
	    } else {
		@stuffing = $self->disco_bare_info($iq->to);
	    }
	    $logger->info("Got disco request for ".$iq->to." returning ".join(', ',@stuffing));
	    if(@stuffing) {
		my $reply = $iq->clone;
		$reply->set_from($iq->to);
		$reply->set_to($from ? $from->as_string : $iq->from);
		$reply->set_connection($iq->connection) if($from);
		$reply->set_attr('{}type', 'result');
		# Now stuff the disco
		$reply->first_element->{children} = \@stuffing;
		# and fire up
		$reply->deliver($self->vh);
		return 1;
	    }
	}
    } elsif((!$iq->to or $iq->to eq $self->vh->name) && $iq->signature eq 'result-{http://jabber.org/protocol/disco#info}query') {
	# This might be responce to our discovery.
	my $node = $iq->first_element->attr('{}node') || "";
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
    my @kids = grep { ref($_) && $_->element_name eq 'publish' } $iq->first_element->children;
    if(!$#kids && $kids[0]->attr('{}node') && $kids[0]->first_element->element_name eq 'item') {
	my $item = $kids[0]->first_element;
	my $node = $kids[0]->attr('{}node');
	$iq->send_result;
	$logger->debug("Publishing PEP events for ".$iq->from);
	$self->publish($iq->from_jid, $node, $item);
	return;
    }
    $iq->send_error
}
sub get_pep {
    my $self = shift;
    my $iq = shift;
    my $from = shift;
    my $what = $iq->first_element->first_element;
    if($what && $what->element_name eq 'items' && $what->attr('{}node')) {
	my $node = $what->attr('{}node');
	unless($self->check_perms($from,$iq->to_jid,$node)) {
	    my $err = $iq->make_error_response(403,'cancel','not-allowed');
	    return $err->deliver($self->vh);
	}
	unless($self->get_pub($iq->to_jid,$node)) {
	    my $ie = $iq->make_error_response(503,'cancel','item-not-found');
	    $logger->debug("Requested node does not exist: ".$ie->as_xml);
	    $ie->deliver($self->vh);
	    return;
	}
	my $event = $self->get_pub_last($iq->to_jid,$node);
	my $res = $iq->clone;
	$res->set_to($iq->from_jid);
	$res->set_from($iq->to_jid);
	$res->set_attr('{}type','result');
	my @items = grep {$_->element_name eq 'items' && $_->attr('{}node') && $_->attr('{}node') eq $node}
			map {$_->children }
			    grep {$_->element_name eq 'event'}
				$event->children
				    if($event && ref($event));
	@items=("<items node='$node'/>") unless(@items);
	$res->first_element->{children} = [@items];
	$res->deliver($self->vh);
    } else {
	$logger->error("GET UNKNOWN PEP ".$iq->as_xml);
    }
}

sub check_perms {
    my $self = shift;
    my $from = shift;
    my $user = shift;
    my $node = shift;
    # Check implied (own resource) subscription
    return 1 if($from->as_bare_string eq $user->as_bare_string);
    # Check subscriber's publishers cache which flags whether autosubscription is allowed by presence
    return 1 if($self->get_subpub($from->as_bare_string,$user->as_bare_string));
    # Check explicit (existing) subscription to the node
    return 1 if($node && $self->get_pub($user,$node,$from->as_bare_string));
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
    if($from && !$from->is_bare && $stanza->attr('{}id') =~ /^pep-event-(\d+)$/) {
	# Validate sequence
	if($1 < $self->{id}) {
	    # Passed entry sanity check, capture and handle if possible
	    my ($err) = grep{$_->element_name eq 'error'}$stanza->children;
	    if($err && $err->attr('{}type') eq 'cancel') {
		my ($event) = grep{$_->element_name eq 'event'} $stanza->children;
		if($event && $event->first_element->element_name eq 'items' && $event->first_element->attr('{}node')) {
		    my $node = $event->first_element->attr('{}node');
		    if($self->get_pub($stanza->to,$node,$from->as_bare_string,$from->as_string)) {
			$logger->info("Error received from ".$from->as_string.", unsubscribing from ".$node);
			$self->get_pub($stanza->to,$node,$from->as_bare_string,$from->as_string,0);
		    } else {
			$logger->info("Error received from ".$from->as_string." for ".$node." on bare push, cannot unsubscribe bare");
		    }
		} else {
		    $logger->info("Error received from ".$from->as_string." but error misses event body, cannot handle and ignore");
		}
	    } elsif($err) {
		$logger->info("Error received from ".$from->as_string." however error is transient(".$err->attr('{}type').") so ignoring it");
	    } else {
		$logger->info("Error received from ".$from->as_string." however error descriptor is missing so ignoring it");
	    }
	    return 1;
	}
    }
    return 0;
}

=head2 emit($self, $event, $to)

The method is used to send published event to subscribed users.

It adds sender and id attribute to the cloned stanza and delivers it via vhost.
=cut

sub emit {
    my $self = shift;
    my $event = shift;
    my $to = shift;
    if($event && ref($event) && UNIVERSAL::isa($event,'DJabberd::Stanza')) {
	my $e = $event->clone;
	$e->set_to($to);
	$e->set_attr('{}id','pep-event-'.($self->{id}++));
	$logger->debug("Emitting PEP Event: ".$e->as_xml);
	$e->deliver($self->vh);
    }
}

=head2 publish($self,$user,$node,$item)

This method is used to push the event $item published by $user for topic $node to all subscribers.

$user is DJabberd::JID object. $node is a string representing pubsub node. $item - a DJabberd::XMLElement object
which was part of the original publish IQ.

It pushes an Event (<message type='headline'><event><item/></event></message>) in three stages. First delivers
it to all $user's connected resources. Then it sends to all explicit subscriptions (known full JIDs). Finally it
broadcasts to the remaining roster items with both/to subscription state - similar to presence broadcast.

The Event (DJabberd::Message object) is stored as last event - to be delivered to accoutns appearing online.

=cut

sub publish {
    my $self = shift;
    my $user = shift;
    my $node = shift;
    my $item = shift;
    my $event = DJabberd::Message->new('','message',{'{}from'=>$user->as_bare_string, '{}type'=>'headline'}, [
	DJabberd::XMLElement->new('','addresses',{xmlns=>'http://jabber.org/protocol/address'},[
		DJabberd::XMLElement->new('','address',{type=>'replyto', jid => $user->as_string},[])
	]),
	DJabberd::XMLElement->new('','event',{xmlns=>PUBSUBNS.'#event'}, [
	    DJabberd::XMLElement->new('','items',{node=>$node},[$item])
	]),
    ]);
    $logger->debug("Publishing stuff: $node ".$item->as_xml);
    # All user's resources are implicitly subscribed to all PEP events disregarding their capabilities.
    foreach my$con($self->vh->find_conns_of_bare($user)) {
	$self->emit($event,$con->bound_jid);
    }
    my $pub = $self->get_pub($user,$node);
    if(ref($pub)) {
	# Now walk through known subscribers
	foreach my$bare(keys(%{$pub})) {
	    next if($bare eq 'last');
	    foreach my$full(keys(%{$pub->{$bare}})) {
		next unless($pub->{$bare}->{$full}); # Negative subscription - filtered out
		$self->emit($event,$full);
	    }
	}
    } else {
	$self->set_pub($user,$node);
    }
    # Then try to figure something from Roster and Subs
    $self->vh->get_roster($user,on_success=>sub {
	my $roster = shift;
	foreach my$ri($roster->from_items) {
	    # check and skip if we have explicit full subsriptions for this bare as [XEP-0163 4.3.2] orders
	    my $ps = $self->get_pub($user,$node,$ri->jid->as_bare_string);
	    next if($ps && ref($ps) eq 'HASH' && values(%{$ps}));
	    # No valid explicit subscriptions, check if we can build one
	    # But first let's register publisher at subscriber's cache
	    $self->set_subpub($ri->jid->as_bare_string,$user->as_bare_string);
	    my $sub = $self->get_sub($ri->jid);
	    if($sub && ref($sub) eq 'HASH') {
		# We may have presence data collected already, let see
		my @jids = grep{$_ ne 'pub'}keys(%{$sub});
		if(@jids) {
		    # We do indeed.
		    foreach my$sjid(@jids) {
			my @topics = grep{$_ eq $node}@{$sub->{$sjid}->{topics}};
			if(!$sub->{$sjid}->{node} || @topics) {
			    # User doesn't have caps or is interested in node notify
			    $logger->debug("Subscribing $sjid to $node and pushing event");
			    $self->set_pub($user,$node,$ri->as_bare_string,$sjid);
			    $self->emit($event,$sjid);
			} else {
			    # User sent caps and they don't contain this node
			    $self->set_pub($user,$node,$ri->as_bare_string,$sjid,0);
			    $logger->debug("User $sjid doesn't want to receive $node events");
			}
		    }
		    next;
		}
	    }
	    # If we have no presence cache - we're likely starting up, let's skip flooding till we get one
	    next unless($self->get_sub);
	    # No presence knowledge, push to the bare
	    $self->emit($event,$ri->jid->as_bare_string);
	}
    });
    # And finally store for later use (new contacts)
    $event->push_child( DJabberd::XMLElement->new('','delay',{xmlns=>'urn:xmpp:delay', stamp=>strftime("%Y-%m-%dT%H:%M:%SZ",gmtime)},[]) );
    $self->set_pub_last($user,$node,$event);
}

=head2 subscribe_to($self, $pub_jid, $node, $sub_jid)

Set user's explicit subscription and push last event from node to him

=cut

sub subscribe_to {
    my $self = shift;
    my $pubj = shift;
    my $node = shift;
    my $user = shift;
    return unless($self->get_pub($pubj,$node)); # node is not published by jid
    # Flag the full jid under bare as active for node of pubj
    $self->set_pub($pubj,$node,$user->as_bare_string,$user->as_string,1);
    # Once subscribed - last event should be pushed.
    $self->emit($self->get_pub_last($pubj,$node),$user);
}

=head2 unsubscribe($self, $bpub, $bsub)

This method supposed to be used when presence subscription between bare pub and
bare sub has changed AND corresponding info is reflected in the publisher's
roster. As such this method must be called from RosterChange hook, not presence
subscription type stanza.

If called from presence - cache may go out-of-sync when following happens:
subscriber removes subscription (presence sent), all relationships removed,
publishers receives notification and looks at client. It's status changes
which pushes new event through PEP. PEP builds new relationship from Roster.

=cut

sub unsubscribe {
    my $self = shift;
    my $sub = shift;
    my $pub = shift;
    # Filter out subscriber's jid from all publisher's topics (pubsub nodes)
    foreach my$topic(keys(%{$self->{pub}->{$pub}})) {
	delete $self->{pub}->{$pub}->{$topic}->{$sub};
    }
    # also remove publisher from subscriber's cache
    $self->set_subpub($sub,$pub,0);
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
    my $user = shift;
    # Subsription attempt, may come from either presence event (auto) or explicit subscription request
    $logger->debug("Subscribing user ".$user->as_string." to ".join(', ',@{$self->get_sub($user)->{topics}}));
    # Assuming prsence event - so iterate through roster and find all publishers with both/from presence
    my @pubs = $self->get_subpub($user->as_bare_string);
    return unless(@pubs); # no one is publishing to the user. TODO: explicit won't work here
    my $sub = $self->get_sub($user);
    return if($sub && $sub->{node} && !@{$sub->{topics}}); # We don't need no notifications
    my @topics = @{$sub->{topics}} if($sub && ref($sub) eq 'HASH' && ref($sub->{topics}) eq 'ARRAY');
    my %old = map {($_ => 1)} @_;
    $logger->debug("User ".$user->as_string." doesn't mind getting PEP events: ".(@topics ? join(', ',@topics):'all'));
    foreach my$bpub(@pubs) {
	unless($self->get_pub($bpub)) {
	    $logger->error("Relationship corruption: publisher $bpub exists for subscriber ".$user->as_string." but is missing in publishers list, removing");
	    $self->set_subpub($user->as_bare_string,$bpub,0);
	    next;
	}
	$logger->debug('Subscribing '.$user->as_string." to $bpub`s PEP events");
	if($sub && $sub->{node}) {
	    # Let's walk through user's interest list and subscribe to matching nodes
	    foreach my$t(@topics) {
		$self->subscribe_to($bpub,$t,$user);
		delete $old{$t};
	    }
	    $logger->debug("Unsubscribing ".$user->as_string." from ".join('. ',keys(%old))) if(%old);
	    foreach my$t(keys(%old)) {
		# Unsubscribe remaining extra
		next unless($self->get_pub($bpub,$t)); # node is not published by jid
		$self->set_pub($bpub,$t,$user->as_bare_string,$user->as_string,0);
	    }
	} else {
	    # No interests - let's subscribe to all available
	    foreach my$t($self->get_pub_nodes($bpub)) {
		$self->subscribe_to($bpub,$t,$user);
	    }
	}
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
scalar value of hash algorithm. This indicates that we actively looking to obtain user caps
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

is DJabberd::JID object of the publisher.

=item $node

is string representing pubsub node - that is a PEP topic, like C<http://jabber.org/protocol/tune>

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
    my $bsub = shift;
    return $self->{pub}->{$bare}->{$node} unless($bsub);
    return undef unless(exists $self->{pub}->{$bare}->{$node}->{$bsub} && ref($self->{pub}->{$bare}->{$node}->{$bsub}) eq 'HASH');
    my $full = shift;
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

=head2 get_pub_last($self, $user, $node)
=cut
=head2 set_pub_last($self, $user, $node, $event)

Fetches and sets last event published by the user to given pubsub node.

$event is a DJabberd::Message object of type headline containing PEP event
(item).

=cut

sub get_pub_last {
    my $self = shift;
    my $user = shift;
    my $node = shift;
    my $pub = $self->get_pub($user,$node);
    return undef unless($pub && ref($pub) eq 'HASH' && exists $pub->{last});
    return $pub->{last};
}
sub set_pub_last {
    my $self = shift;
    my $user = shift;
    my $node = shift;
    my $pub = $self->set_pub($user,$node);
    $pub->{last} = $_[0];
}

=head2 get_pub_nodes($self, $user)

A method which returns all (auto-)created pubsub nodes for the given root
collector represented by bare JID.

Returns array of strings representing pubsub nodeID
=cut

sub get_pub_nodes {
    my $self = shift;
    my $user = shift;
    my $pub = $self->get_pub($user);
    return () unless($pub && ref($pub) eq 'HASH');
    return grep{$_ ne 'last'} keys(%{$pub});
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

Subscriber's state is a hint, it's not used actively during delivery.  The state
is set when user sends available presence(goes online) with entity caps visible
on PEP service.

PEP then resolves caps figuring C<+notify> topics and sets them in subscription
state. If later publisher goes online it will use the pre-set hints for
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
    my $self = shift;
    my $user = shift;
    return grep{$_ ne 'pub'}map{keys(%{$_})}values(%{$self->{sub}}) unless($user);
    return $self->{sub}->{$user} unless(ref($user)); # bare jid string
    return $self->{sub}->{$user->as_bare_string}->{$user->as_string};
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

=head2 get_subpub($self, $bsub[, $bpub])
=cut
=head2 set_subpub($self, $bsub, $bpub[, $val])

These calls are used to manage subscriber-to-publisher relationship.

Since subscribers can be remote users we cannot get their roster and resovle
their publishers. Iterating through all publishers and their rosters is tedious
work. Hence this fast lookup cache is built when publisher pushes the event to
the contact on the roster.

$bsub and $bpub are strings representing bare jid of the subscriber and publisher.

When $val is provided and is 0 - set_subpub call will remove the relationship.
Otherwise - when it's not provided or is 1 - will set the relationship.

When presence or caps of the user received - get_subpub will be used to build
specific subscriptions to stop broadcasting events to bare jid and instead
push them to interested resources only.

In other words - C<if(get_subpub($contact,$user))> tells that B<$user> allows
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
    return $self->{sub}->{$bsub}->{pub}->{$bpub} = 1 if(!@_ or $_[0]); # implicit or explicit set
    return delete $self->{sub}->{$bsub}->{pub}->{$bpub}; # this was a removal call
}

=head2 del_pubsub()

The call intended to clean up the mess after previous two.

Actually it tries to remove all bi-directional references between publisher and subscriber but only to remove
explicit full jid subscription without touching global state. In other words - to reverse explicit subscription
relationship built on presence/caps reception. Hence it should be used in unavailable presence handler.
=cut

sub del_subpub {
    my $self = shift;
    my $user = shift;
    return unless($user && ref($user) && !$user->is_bare);
    foreach my$p(keys(%{$self->{sub}->{$user->as_bare_string}->{pub}})) {
	my @nodes;
	if($self->{sub}->{$user->as_bare_string}->{$user->as_string}->{node}) {
	    @nodes = $self->get_sub_nodes($user);
	} else {
	    @nodes = $self->get_pub_nodes($p);
	}
	foreach my$n(@nodes) {
	    delete $self->{pub}->{$n}->{$user->as_bare_string}->{$user->as_string}
	}
    }
    delete $self->{sub}->{$user->as_bare_string}->{$user->as_string};
}

=head1 PERSISTENCE

This implementation is memory-only last-only. That is - all pep events are
volatile, PEP node just distributes events in real-time, caching last published
event only, which will be pushed to subscriber on subscription (presence).

That last message will not survive server restart however that should not be a
problem because client will re-connect and re-publish its tunes/nicks/moods/etc.

If such last events is required to be persistant - implementation should override
L<set_pub_last> and <get_pub_last> calls, storing the event and calling SUPER.
Also would make sense adding C<persistent-items> feature to the list of supported
features (eg. push(@DJabberd::Plugin::PEP::pubsub_features,'persistent-items');).

Event retrieval is also supported, and will call get_pub_last to fetch the message.

Message is literally DJabberd::Message stanza with type C<headline>, ext-address
set to full jid of the publisher and items/item/<payload> content.

=cut

=head1 INTERNALS
=cut
=head2 Event flow

Publish -> send headlines to subscribed resources -> get roster -> walk through both/to resources -> push to bare jid -> store last event

Note: all publisher's resources are implicitly subscribed (as presence is)

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
used.  It's supposed to be fully managed through get/set_pub methods however it
could be fully managed by those calls, up to setting/getting entire publisher's
tree.

 $self->{pub}->{'publisher_bare_jid'} = {
    'pubsub_node1' => {
	last => DJabberd::Message,
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
	last => DJabberd::Message,
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
use this tree to resolve publishers on reception of the disco#info ir presence stanzas with caps.

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
