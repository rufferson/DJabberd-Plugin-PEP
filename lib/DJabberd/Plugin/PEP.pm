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

=cut

my @pubsub_features = (
	'publish',
	'auto-create',
	'auto-subscribe',
	'last-published',
	'access-presence',
	'presence-subscribe',
	'filtered-notifications',
);
sub register {
    my ($self,$vhost) = @_;
    my $manage_cb = sub {
	my ($vh, $cb, $iq) = @_;
	if($iq->isa("DJabberd::IQ")) {
	    if(!$iq->to || $iq->to eq $iq->from || $iq->to eq $vh->name) {
		if ($iq->signature eq 'get-{'.PUBSUBNS.'}pubsub') {
		    $logger->debug("PEP Query: ".$iq->as_xml);
		    $self->get_pep($iq);
		    $cb->stop_chain;
		    return;
		} elsif ($iq->signature eq 'set-{'.PUBSUBNS.'}pubsub') {
		    $logger->debug("PEP Modify: ".$iq->as_xml);
		    $self->set_pep($iq);
		    $cb->stop_chain;
		    return;
		}
	    } elsif($self->disco_bare_jid($iq,$iq->connection->bound_jid)) {
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
	if($iq->isa("DJabberd::IQ") && $iq->to && $iq->from && $self->disco_bare_jid($iq,$iq->connection->bound_jid)) {
	    $cb->stop_chain;
	} elsif($iq->isa("DJabberd::Presence")) {
	    # Presence registration/check
	    $self->handle_presence($iq);
	} elsif($iq->isa("DJabberd::Message") and $iq->to and $iq->to_jid->is_bare and $vh->handles_jid($iq->to_jid) and $iq->attr('{}type') eq 'error') {
	    return $cb->stop_chain if($self->handle_error($iq));
	}
	$cb->decline;
    };
    my $cleanup_cb = sub {
	my ($vh, $cb, $conn) = @_;
	if($conn && $conn->isa('DJabberd::Connection::ClientIn') && $conn->bound_jid) {
	    $self->cleanup($conn->bound_jid);
	}
	$cb->decline;
    };
    $self->{vhost} = $vhost;
    $vhost->register_hook("switch_incoming_client",$manage_cb);
    $vhost->register_hook("switch_incoming_server",$handle_cb);
    $vhost->register_hook("ConnectionClosing",$cleanup_cb);
    $vhost->register_hook("AlterPresenceUnavailable",$cleanup_cb);
    $vhost->caps->add(DJabberd::Caps::Identity->new("pubsub","pep","djabberd"));
    foreach my $psf(@pubsub_features) {
	$vhost->caps->add(DJabberd::Caps::Feature->new(PUBSUBNS.'#'.$psf));
    }
    $self->{id} = 0;
}

sub vh {
    return $_[0]->{vhost};
}

sub cleanup {
    my $self = shift;
    my $jid = shift;
    # Wait, there could be more resources publishing. Let's remove the nodes explicitly only
    #delete $self->{pub}->{$conn->bound_jid->as_bare_string};
    # But subscriptions is something we can really remove
    delete $self->{sub}->{$jid->as_bare_string};
}
sub handle_presence {
    my $self = shift;
    my $pres = shift;
    my $type = $pres->attr('{}type') || 'available';
    my $jid = $pres->from_jid || $pres->connection->bound_jid;
    return unless($jid && (!$pres->to or $self->vh->handles_jid($pres->to_jid)));
    if($type eq 'available') {
	my ($nver,$cap);
	my ($c) = grep{ ref($_) && $_->element_name eq 'c' && ($_->attr('{}xmlns') || '') eq 'http://jabber.org/protocol/caps'} $pres->children;
	if($c && ref($c) && $c->isa('DJabberd::XMLElement')) {
	    my $ver = $c->attr('{}ver');
	    my $node = $c->attr('{}node');
	    my $hash = $c->attr('{}hash');
	    if($ver && $node && $hash) {
		$nver = "$node#$ver";
		$cap = $self->get_cap($nver);
		# The presence came to our account, so we need to know its filters even if we have no publishers at the moment
		if(!$cap or !exists $cap->{caps}) {
		    $self->set_cap($nver,$hash);
		    my $iq = DJabberd::IQ->new({from=>$self->vh->name,to=>$jid->as_string,type=>'get'},[
			DJabberd::XMLElement->new('','query',{ xmlns=>'http://jabber.org/protocol/disco#info', node=>$nver },[])
		    ]);
		    $iq->set_attr('{}id','pep-iq-'.$self->{id}++);
		    $iq->deliver($self->vh);
		    return; # The reset will be done in disco iq result handler
		}
	    }
	}
	# We're here either because we already have caps or contact does not provide them in the presence
	my $sub = $self->get_sub($jid);
	if(!$sub) {
	    # Supposedly it's a first timer. Let's remember it either by calculating subscriptions or flagging empty one
	    if($cap) {
		$self->set_sub($jid,$nver,map{$_->bare}$cap->get('feature'));
	    } else {
		$self->set_sub($jid);
	    }
	    # and subscribe now to all active PEP nodes according to roster/caps if the account is local (we have it's roster)
	    $self->subscribe($jid) if($self->vh->handles_jid($jid));
	}
    } elsif($type eq 'unavailable') {
	$self->cleanup($jid);
    # We really need to do this on roster update, otherswise we'll merely start pushing to bare jid.
    #} elsif($type eq 'unsubscribe' && $pres->from_jid) {
    #	$self->unsub($pres->from_jid->as_bare_string,$pres->to_jid->as_bare_string);
    }
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
	$logger->debug("Our Pezdyuk: ".$iq->as_xml." from ".$from->as_string);
	# Handle explicit discovery of the user's bare jid - represent the user with PEP node.
	if($iq->signature eq 'get-{http://jabber.org/protocol/disco#info}query' or $iq->signature eq 'get-{http://jabber.org/protocol/disco#items}query') {
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
    } elsif((!$iq->to || $iq->to eq $self->vh->name) && $iq->signature eq 'result-{http://jabber.org/protocol/disco#info}query') {
	$logger->debug("Our Pezdyuk: ".join(', ',%{$iq->first_element->attrs}));
	# This might be responce to our discovery.
	my $node = $iq->first_element->attr('{}node') || "";
	return 0 unless($node); # It wasn't a reply to our request after all, we're always asking for node
	my $caps = $self->get_cap($node);
	$logger->debug("Pezdyuk has node $node");
	return 0 unless($caps && !ref($caps)); # The node is set but we don't have it cached. Must be not ours either
	$logger->info("Got disco result for ".$node." from ".$iq->from);
	my $cap = DJabberd::Caps->new($iq->first_element->children);
	my $capdgst = $cap->digest($caps);
	my ($nuri,$digest) = split('#',$node);
	if($digest ne $capdgst) {
	    $logger->error("Digest mismatch: worng hashing function ".$caps->{hash}."? $digest vs $capdgst");
	    $node = "$nuri#$capdgst";
	    $self->set_cap($nuri,$capdgst,$cap);
	}
	if(!$self->get_sub($from,$node)) {
	    $self->set_sub($from,$node,map{$_->bare}$cap->get('feature'));
	    $logger->debug("Pending caps received, making subscription for ".$from->as_string);
	    $self->subscribe($from,$node) if($self->vh->handles_jid($from));
	}
	return 1;
    }
    return 0;
}

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
    $logger->error("GET PEP ".$iq->as_xml);
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
    my $event = DJabberd::Message->new({'{}from'=>$user->as_bare_string, '{}type'=>'headline'}, [
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
	foreach my$ri($roster->to_items) {
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
bare sub has changed AND corresponding info is eflected in the publisher's
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

=head2 subscribe($self, $user)

Subscribe $user to all publishers which are pushing events to $user for interested nodes.

Also for each subscribed node - push last event to the user.

$user should be DJabberd::JID object containing full JID.

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
    my @topics = (${$sub && $sub->{topics} || []});
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
The subscribers table is actually filled from this cache. If caps entry is missing - PEP will
explicitly request a service discovery [XEP-0030] for the JID having Entity Caps [XEP-0115]
digest (ver='') in its presence.

$node here is a XEP-0115 node, not pubsub node. This node is usually UserAgent URI.

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
    my $ver  = shift;
    my $caps = shift;
    if($self->{cap}->{"$node#$ver"} and !ref($self->{cap}->{"$node#$ver"})) {
	$self->{cap}->{"$node#$ver"} = { hash => $self->{cap}->{"$node#$ver"}, caps => $caps};
    } else {
	$self->{cap}->{"$node#$ver"} = $caps;
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

$event is a DJabberd::Message object of type headline containing PEP event (item).

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

A method which returns all (auto-)created pubsub nodes for the given root collector represented by bare JID.

Returns array of strings representing pubsub nodeID
=cut

sub get_pub_nodes {
    my $self = shift;
    my $user = shift;
    my $pub = $self->get_pub($user);
    return () unless($pub && ref($pub) eq 'HASH');
    return grep{$_ ne 'last'} keys(%{$pub});
}

=head2 get_sub($self,$user,$node)
=cut
=head2 set_sub($self,$user,$node,(@list))

These calls are used to manage subscriber's state. Subscriber's state is a hint, it's not used actively during delivery.
The state is set when user sends available presence(goes online) with entity caps visible on PEP service.

PEP then resolves caps figuring C<+notify> topics and sets them in subscription state. If later publisher goes online
it will use the pre-set hints for C<filtered-notifications> pubsub feature. Presence without notifications will still
register an entry in sub table, but empty caps entry means catch-all or follow-the-presence.

The @list argument is representing list of features discovered from the client (disco#info result's var list) - from
DJabberd::Caps object received from get_cap call.

=cut

sub get_sub {
    my $self = shift;
    my $user = shift;
    my $node = shift;
    return undef unless($user);
    return $self->{sub}->{$user} unless(ref($user)); # bare jid string
    return $self->{sub}->{$user->as_bare_string}->{$user->as_string};
}
sub set_sub {
    my $self = shift;
    my $user = shift;
    my $node = shift;
    # Node#ver here is used to flag that empty subscription list means exatly that - no interest expressed explicitly for this UserAgent/Caps
    my $sub = { node => $node, topics => []};
    foreach my$f(@_) {
	if($f =~ /^(.+)\+notify$/) {
	    push(@{$sub->{topics}},$1);
	}
    }
    $self->{sub}->{$user->as_bare_string} = { pub => {} } unless(ref($self->{sub}->{$user->as_bare_string}) eq 'HASH');
    $self->{sub}->{$user->as_bare_string}->{$user->as_string} = $sub;
}

=head2 get_subpub($self, $bsub)
=cut
=head2 set_subpub($self, $bsub, $bpub)

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

=cut

sub get_subpub {
    my $self = shift;
    my $bsub = shift;
    return () unless(exists $self->{sub}->{$bsub} && ref($self->{sub}->{$bsub}) && exists $self->{sub}->{$bsub}->{pub});
    return keys(%{$self->{sub}->{$bsub}->{pub}});
}
sub set_subpub {
    my $self = shift;
    my $bsub = shift;
    my $bpub = shift;
    $self->{sub}->{$bsub} = { pub => {} } unless(ref($self->{sub}->{$bsub}) eq 'HASH');
    return $self->{sub}->{$bsub}->{pub}->{$bpub} = 1 if(!@_ or $_[0]); # implicit or explicit set
    return delete $self->{sub}->{$bsub}->{pub}->{$bpub}; # this was a removal call
}
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

You don't normally need these structs as higher level calls (get/set_) should cover general cases.

Capabilities:
$self->{cap}->{"<node>#<digest>"} = { hash => '(sha-1|sha-256|...), caps => DJabberd::Caps }

Publishers:
This is probably the most complex structure - as it's (supposedly) most frequently used.
It's supposed to be fully managed through get/set_pub methods however it could be fully
managed by those calls, up to setting/getting entire publisher's tree.

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

Here "<node>#<digest>" are node and ver fields of XEP-0115 entity capabilities <c> element.

To complete publishers struct for a bare_jid one needs bare_jid's Roster <both and to> and Subscribers struct, where subscribers is built from Caps.

It could be filled in from the opposite end - having publisher's struct one can append it using subscriber's Roster <both and from> and Caps.

C<Subscribers> is rather a filter/preferences list, we will broadcast to bare jid the events unless we have explicit subscription with filters.

=cut
=head1 AUTHOR

Ruslan N. Marchenko, C<< <me at ruff.mobi> >>

=head1 COPYRIGHT & LICENSE

Copyright 2016 Ruslan N. Marchenko, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut
1;
