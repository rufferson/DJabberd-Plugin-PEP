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

##
# Overriden methods
#
sub set_pub_last {
    my ($self, $item, $user, $node, $id) = @_;
    my $ret = $self->SUPER::set_pub_last($item,$user,$node,$id);
    # do the magic
    if($item) {
	$user ||= $item->{user}->as_bare_string;
	$node ||= $item->{node};

	my $cfg = $self->get_pub_cfg($user, $node);
	# Skip this for volatile node
	return $ret unless($cfg->{persist_items});

	$self->store_item($user, $node, $item);

	if($cfg->{max} ne 'max' && $cfg->{max} > 0) {
	    # Retain max most recent items, remove the rest
	    $self->retain($self->node_dname($user, $node), $cfg->{max}, $self->get_pub_last($user, $node, undef, $cfg->{max}));
	}
    } elsif($user && $node && $id) {
	$DJabberd::Plugin::PEP::logger->debug("Retracting item $id of $node at $user");
	unlink($self->item_fname($user,$node,$id)) or warn("Unspool $user/$node/$id: $!");
    } elsif($user && $node) {
	$DJabberd::Plugin::PEP::logger->debug("Purging node $node at $user");
	$self->retain($self->node_dname($user, $node));
    }
    return $ret;
}

sub get_pub_last {
    my ($self, $user, $node, $id, $max) = @_;

    return $self->SUPER::get_pub_last($user, $node, $id, $max) if($max && $max == 1);
    my $cfg = $self->get_pub_cfg($user, $node);
    return $self->SUPER::get_pub_last($user, $node, $id, $max) if(!$cfg || $cfg->{max} == 1);

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
	opendir(my $dh, $dname) or do {
	    $DJabberd::Plugin::PEP::logger->debug("Cannot open node dir $dname: $!");
	    return $self->SUPER::get_pub_last($user, $node, $id, $max);
	};
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
	@ret = $self->SUPER::get_pub_last($user, $node, $id, $max) unless(@ret);
	return @ret;
    }
}

sub set_pub_cfg {
    my ($self, $user, $node, $cfg) = @_;
    # fetch old cfg
    my $ocfg = $self->get_pub_cfg($user, $node, 1);
    return $ocfg unless($ocfg);
    $ocfg = { %{ $ocfg } };
    $cfg = $self->SUPER::set_pub_cfg($user, $node, $cfg);
    return $cfg unless($cfg);
    my $dname = $self->node_dname($user,$node);
    File::Path::make_path($dname) unless(-d $dname);
    nstore $cfg, "$dname/+cfg+" or die("Cannot store config for node $node at $user");
    # now process the delta
    if(!$ocfg->{persist_items} && $cfg->{persist_items}) {
	# we need to store current last
	$DJabberd::Plugin::PEP::logger->debug("Persistence is enabled for $node on $user");
	my $item = $self->SUPER::get_pub_last($user, $node);
	$self->store_item($user, $node, $item) if($item);
    } elsif($ocfg->{persist_items} && !$cfg->{persist_items}) {
	# we need to wipe the storage
	$DJabberd::Plugin::PEP::logger->debug("Persistence is disabled for $node on $user");
	$self->retain($dname);
    } elsif($cfg->{persist_items}) {
	# no changes in persistance but we're storing
	if($ocfg->{max} && 
	  (!exists $cfg->{max} || 
	    ($cfg->{max} ne 'max' &&
	      ($ocfg->{max} eq 'max' ||
	       $cfg->{max} < $ocfg->{max})
	    )
	  )
	)
	{
	    # So if max was defined (was not 1) and now max is not defined (is 1)
	    # or is defined and is not max but is less than old max (considering
	    # possible unlimited values at both sides) we may need to shrink the
	    # storage
	    $DJabberd::Plugin::PEP::logger->debug("Max was is decreased for $node on $user to ".$cfg->{max});
	    $self->retain($dname, $cfg->{max}, $self->get_pub_last($user,$node,undef,$cfg->{max}));
	}
    } else {
	$DJabberd::Plugin::PEP::logger->debug("Cfg for $node on $user: Max ".$cfg->{max}." persist ".(defined $ocfg->{persist_items}?$ocfg->{persist_items}:'undef')."<>".(defined$cfg->{persist_items}?$cfg->{persist_items}:'undef'));
    }
    return $cfg;
}

sub del_pub {
    my ($self, $user, $node) = @_;
    $self->SUPER::del_pub($user, $node);
    # and clear the storage now
    my $dnode = $self->node_dname($user, $node);
    File::Path::remove_tree($dnode) or
	$DJabberd::Plugin::PEP::logger->debug("Cannot remove node spool dir: $!");
}

##
# Internal methods
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
sub store_item {
    my ($self, $user, $node, $item) = @_;
    my $dname = $self->node_dname($user, $node);
    my $fname = $self->item_fname($item);
    my $fitem = { %{ $item } };
    $DJabberd::Plugin::PEP::logger->debug("Storing item ".$item->{id}." for $node on $user");
    (File::Path::make_path($dname) or die("Cannot create node dir for $node at $user: $!"))
	unless(-d $dname);

    $fitem->{user} = $item->{user}->as_string;

    die("PEP cannot spool $fname: ".$!) unless(nstore($fitem, $fname));
    
    utime($item->{ts}, $item->{ts}, $fname) or warn("Cannot touch $fname: $!");
    return $fname;
}
sub retain {
    my ($self, $dname, $max, @keep) = @_;
    if($max && @keep) {
	if($max == scalar @keep) {
	    # if keep is at max we may have spare item to drop
	    my %ids = map{($_->{id}=>1)}@keep;
	    opendir(my $dh, $dname) or die("Cannot open node dir $dname: $!");
	    while(my $fn = readdir $dh) {
		next if($fn =~ /^(?:\.|\.\.|\+cfg\+)/);
		my $id = MIME::Base64::decode_base64url($fn);
		next if($ids{$id});
		$DJabberd::Plugin::PEP::logger->debug("Wiping $id($fn) above the $max");
		unlink("$dname/$fn") or warn("Cannot unlink $dname/$fn: $!");
	    }
	}
    } else {
	opendir(my $dh, $dname) or do {
	    $DJabberd::Plugin::PEP::logger->debug("Cannot open node dir $dname: $!");
	    return;
	};
	while(readdir $dh) {
	    next if(/^(?:\.|\.\.|\+cfg\+)/);
	    unlink("$dname/$_") or warn("Cannot unlink $dname/$_: $!");
	}
    }
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
		$self->set_pub($jid,$node);
		my $cfg = retrieve $self->{spool}."/$dn/$nn/+cfg+"
		    if(-f $self->{spool}."/$dn/$nn/+cfg+");
		if($cfg) {
		    $DJabberd::Plugin::PEP::logger->debug("Restored config for node $node on $jid");
		    $self->SUPER::set_pub_cfg($jid, $node, $cfg);
		}
		my ($last) = $self->get_pub_last($jid, $node, undef, -1);
		$self->SUPER::set_pub_last($last);
		$DJabberd::Plugin::PEP::logger->debug("Restored node $node on $jid with cfg ".($cfg || 'undef')." and last ".($last || 'undef'));
	    }
	    closedir($pub);
	}
	closedir($spool);
    }
}

1;
