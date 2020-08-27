package DJabberd::Plugin::PEP::Spool;
use 5.012;
use strict;
use warnings;
use base 'DJabberd::Plugin::PEP';
use Storable qw(nstore retrieve);
use File::Path;

sub set_config_spool_dir {
    $_[0]->{spool} = $_[1];
}

sub finalize {
    my $self = shift;
    $self->{spool} ||= 'pep';
    if($self->{spool} && ! -d $self->{spool}) {
	mkdir($self->{spool}) or $self->SUPER::logger->logdie("Spool dir: $!");
	return;
    }
    open(my $FH, '>@@rwcheck@@') or $self->SUPER::logger->logdie("Spool RW Check: $!");
    unlink($FH);
    close($FH);
}

sub register {
    my $self = shift;
    push(@DJabbberd::Plugin::PEP::pubsub_features, 'persistent-items', 'multi-items', 'delete-items');
    $self->{vhost} = $_[0];
    $DJabberd::Plugin::PEP::logger->debug("Despooling ".$self->{spool}." on ".$self->vh);
    $self->despool();
    $self->SUPER::register(@_);
}

sub user_dname {
    my ($self, $jid) = @_;
    my $user = MIME::Base64::encode_base64url((ref $jid ? $jid->as_bare_string : $jid));
    return $self->{spool}.'/'.$user;
}
sub node_dname {
    my ($self, $jid, $nid) = @_;
    my $user = MIME::Base64::encode_base64url((ref $jid ? $jid->as_bare_string : $jid));
    my $node = MIME::Base64::encode_base64url($nid);
    return $self->{spool}.'/'.$user.'/'.$node;
}
sub item_fname {
    my ($self, $item, $jid, $nid, $iid) = @_;
    my $user = MIME::Base64::encode_base64url(($item ? $item->{user} : $jid)->as_bare_string);
    my $node = MIME::Base64::encode_base64url(($item ? $item->{node} : $nid));
    my $id   = MIME::Base64::encode_base64url(($item ? $item->{id} : $iid));
    return $self->{spool}.'/'.$user.'/'.$node.'/'.$id;
}
sub set_pub_last {
    my ($self, $item, $user, $node, $id) = @_;
    $self->SUPER::set_pub_last($item,$user,$node,$id);
    # do the magic
    if($item) {
	$user ||= $item->{user}->as_bare_string;
	$node ||= $item->{node};
	$id ||= $item->{id};
	my $dname = $self->node_dname($user, $node);
	my $fname = $self->item_fname($item);
	$DJabberd::Plugin::PEP::logger->debug("Setting item ".$id." for ".$node." at ".$user);
	(File::Path::make_path($dname) or die("Cannot create node dir for $node at $user: $!"))
	    unless(-d $dname);
	my $fitem = { %{ $item } };
	$fitem->{user} = $item->{user}->as_string;
	unless(nstore($fitem, $fname)) {
	    die("PEP cannot spool $fname: ".$!);
	}
	utime($item->{ts}, $item->{ts}, $fname) or warn("Cannot touch $fname: $!");
    } elsif($user && $node && $id) {
	$DJabberd::Plugin::PEP::logger->debug("Retracting item $id of $node at $user");
	unlink($self->item_fname($user,$node,$id)) or warn("Unspool $user/$node/$id: $!");
    } elsif($user && $node) {
	my $dname = $self->node_dname($user, $node);
	opendir(my $dh, $dname) or die("Cannot open node dir $dname: $!");
	$DJabberd::Plugin::PEP::logger->debug("Purging node $node at $user");
	while(readdir $dh) {
	    next if(/^(?:\.|\.\.|\+cfg\+)/);
	    unlink("$dname/$_") or warn("Cannot unlink $dname/$_: $!");
	}
    }
}
sub get_pub_last {
    my ($self, $user, $node, $id, $max) = @_;
    return $self->SUPER::get_pub_last($user, $node, $id, $max) if($max && $max == 1);
    # Retrieve all or specific
    if($id) {
	my $fname = $self->item_fname(undef,$user,$node,$id);
	my $fitem;
	$DJabberd::Plugin::PEP::logger->debug("Retrieving file $fname for $user/$node/$id");
	eval {
	    $fitem = retrieve $fname or warn("Retrieve $fname for $user, $node, $id: $!");
	    $fitem->{user} = DJabberd::JID->new($fitem->{user});
	} or $DJabberd::Plugin::PEP::logger->info($@);
	return $fitem;
    } else {
	$DJabberd::Plugin::PEP::logger->debug("Listing node $node at $user");
	my @fitems;
	my @ret;
	my ($start,$stop);
	my $dname = $self->node_dname($user, $node);
	opendir(my $dh, $dname) or die("Cannot open node dir $dname: $!");
	while(my $fn = readdir $dh) {
	    next if($fn =~ /^(?:\.|\.\.|\+cfg\+)/);
	    $DJabberd::Plugin::PEP::logger->debug("Adding file $fn of $node at $user to the stash");
	    my $mt = (stat "$dname/$fn")[9];
	    if(!@fitems || $mt > $fitems[-1]->[1]) {
		unshift(@fitems, [ $fn, $mt]);
	    } elsif($mt <= $fitems[0]->[1]) {
		push(@fitems, [ $fn, $mt ]);
	    } else {
		for my$i(0..$#fitems) {
		    if($mt <= $fitems[$i]->[1] && $fitems[$i+1]->[1] < $mt) {
			splice(@fitems, $i, 0, [$fn, $mt]);
			last;
		    }
		}
	    }
	}
	close($dh);
	if(!$max) {
	    # by default return 10 first items - last in the list
	    $start = List::Util::max($#fitems - 10, 0);
	    $start = 0 if($start < 0);
	    $stop = $#fitems;
	} elsif($max == -1) {
	    # special case to override super - for despool
	    $start = $stop = 0;
	} elsif($max eq 'max') {
	    $start = 0;
	    $stop = $#fitems;
	} elsif($max > 0) {
	    # here we return max last items - first in the list
	    $start = 0;
	    $stop = $max - 1;
	} else {
	    die("Unknown max value: $max");
	}
	# Return max first items
	for my $fi(@fitems[$start..$stop]) {
	    next unless($fi);
	    $DJabberd::Plugin::PEP::logger->debug("Restoring $dname/".$fi->[0]);
	    my $fitem = retrieve $dname.'/'.$fi->[0] or die("Retrieve: $!");
	    $fitem->{user} = DJabberd::JID->new($fitem->{user});
	    push(@ret,$fitem);
	}
	return @ret;
    }
}
sub set_pub_cfg {
    my ($self, $user, $node, $cfg) = @_;
    $self->SUPER::set_pub_cfg($user, $node, $cfg);
    $cfg = $self->get_pub_cfg($user, $node, 1);
    my $dname = $self->node_dname($user,$node);
    File::Path::make_path($dname) unless(-d $dname);
    nstore $cfg, "$dname/+cfg+" or die("Cannot store config for node $node at $user");
}
sub del_pub {
    my ($self, $user, $node) = @_;
    $self->SUPER::del_pub($user, $node);
    # and clear the storage now
    my $dnode = $self->node_dname($user, $node);
    File::Path::remove_tree($dnode) or die("Cannot remove node spool dir");
}

sub despool {
    my $self = shift;
    if(opendir(my$spool,$self->{spool})) {
	# bares - pubs
	while(my$dn = readdir($spool)) {
	    next if($dn eq '.' or $dn eq '..' or ! -d $self->{spool}."/$dn");
	    my $jid = DJabberd::JID->new(MIME::Base64::decode_base64url($dn));
	    unless($self->vh->handles_jid($jid)) {
		$DJabberd::Plugin::PEP::logger->warn("Unsupported JID translated from $dn");
		next;
	    }
	    opendir(my$pub,$self->{spool}."/$dn") or die($!);
	    while(my$nn = readdir($pub)) {
		next if($nn eq '.' or $nn eq '..' or ! -d $self->{spool}."/$dn/$nn");
		my $node = MIME::Base64::decode_base64url($nn);
		my ($last) = $self->get_pub_last($jid, $node, undef, -1);
		my $cfg = retrieve $self->{spool}."/$dn/$nn/+cfg+"
		    if(-f $self->{spool}."/$dn/$nn/+cfg+");
		if($cfg) {
		    $self->SUPER::set_pub_cfg($jid, $node, $cfg);
		} else {
		    $self->set_pub($jid,$node);
		}
		$self->SUPER::set_pub_last($last);
		$DJabberd::Plugin::PEP::logger->debug("Restored node $node on $jid with cfg ".($cfg || 'undef')." and last ".($last || 'undef'));
	    }
	    closedir($pub);
	}
	closedir($spool);
    }
}

1;
