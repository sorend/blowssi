#!/usr/bin/perl -w

# blowssi - an mircryption/FiSH compatible irssi script
# Copyright (C) 2009 John Sennesael
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

use Crypt::ircBlowfish;
use Crypt::CBC;
use MIME::Base64;
use Crypt::ircDH1080;

use Irssi::Irc;
use Irssi;
use vars qw($VERSION %IRSSI);

use strict;

# irssi package info
my $VERSION = "0.2.1";
my %IRSSI = (
    authors => "John \"Gothi[c]\" Sennesael & Tanesha & Soren A D",
    contact => "sorend\@gmail.com",
    name => 'blowssi',
    description => 'Fish and mircryption compatible blowfish/cbc encryption (+dh1080 keyx)',
    license => 'GNU GPL v3',
    url => 'https://github.com/sorend/blowssi'
);


my @prefixes = ('+OK ','mcps ');
my %channels;
my $config_file = sprintf("%s/blowssi.conf", Irssi::get_irssi_dir());
my $blowfish = Crypt::ircBlowfish->new;
my $dh1080 = Crypt::ircDH1080->new;
my $keyx_cbc = 0;

# ----------------- subroutines --------------------

# blows up a key so it matches 56 bytes.
sub blowkey {
    # get params
    my $key = @_[0];
    my $orig_key = $key;
    # don't need to do anything if it's already big enough.
    if (length($key) >= 8) {
        return $key;
    }
    # keep adding the key to itself until it's larger than 8 bytes.
    while (length($key) < 8) {
        $key .= $key;
    }
    return $key;
}

# loads configuration
sub loadconf {
    open CONF, "<$config_file" || return;
    my @conf = <CONF>;
    close CONF;
    foreach my $ck (@conf) {
        chomp $ck;
        my @a = map { s/^\s+|\s+$//g; $_ } split /:/, $ck;
        next unless 2 == @a;
        $channels{$a[0]} = $a[1];
    }
    Irssi::print("\00314- configuration file loaded " . scalar(keys %channels) . " keys");
}

sub saveconf {
    open CONF, ">$config_file" || die "Error writing config file $!";
    while (my ($c, $k) = each(%channels)) {
        next if $k =~ /^keyx:/;
        print CONF "$c:$k\n" if $c && $k;
    }
    close CONF;
}

sub delkey {
    my ($channel) = @_;

    # check user sanity
    unless ($channel) {
        Irssi::print("No channel specified. Syntax: /blowdel channel");
        return 1;
    }

    delete $channels{$channel};
    saveconf();
    Irssi::print("Key deleted, and no longer using encryption for $channel");
}

# calculates privmsg length.
sub irclen {
    my ($len,$curchan,$nick,$userhost) = @_;

    # calculate length of "PRIVMSG #blowtest :{blow} 4b7257724a ..." does not exceed
    # it may not exceed 511 bytes
    # result gets handled by caller.

    return ($len + length($curchan) + length("PRIVMSG : ") + length($userhost) + 1 + length($nick) );
}

# turn on blowfish encryption
sub blowon {
    Irssi::settings_set_bool("docrypt", 1);
    Irssi::print("Blowfish encryption/decryption enabled");
}

# turn off blowfish encryption
sub blowoff {
    Irssi::settings_set_bool("docrypt", 0);
    Irssi::print("Blowfish encryption/decryption disabled");
}

# change encryption key
sub setkey {
    my ($channel, $key) = split / /, $_[0], 2;

    unless ($key && $channel) {
        Irssi::print("Current configuration..");
        foreach my $k (keys %channels) {
            Irssi::print("$k -> $channels{$k}");
        }
        return;
    }

    # check user sanity
    unless ($channel) {
        Irssi::print("Error: no channel specified. Syntax is /blowkey channel key");
        return 1;
    }
    unless ($key) {
        Irssi::print("Error: no key specified. Syntax is /blowkey channel key");
        return 1;
    }
    $channels{$channel} = $key;
    saveconf();
    Irssi::print("Key for $channel set to $key");
}

sub blowhelp {
    Irssi::print("$IRSSI{description}");
    Irssi::print("Commands");
    Irssi::print("---------------------------------------------------------------");
    Irssi::print("/blowhelp                       Show this help");
    Irssi::print("/blowon                         Turn blowfish back on.");
    Irssi::print("/blowoff                        Temporarily disable all blowfish.");
    Irssi::print("/blowkey <user|chan> <key>      Statically set key for a channel.");
    Irssi::print("/blowkeyx <cbc|ebc> <user|chan> Perform DH1080 key exchange with user.");
    Irssi::print("/blowdel <user|chan>            Remove key for user.");
    Irssi::print("");
}

sub keyx {
    # get params
    my ($params, $server, $winit) = @_;
    my ($method, $user) = split /\s/, $params;
    # check encryption method validity
    unless ($method =~ /^(cbc|ecb)$/) {
        Irssi::print("Error: unknown method: $method. Specify either cbc or ecb. Syntax is /blowkeyx method nickname");
        return 1;
    }
    # check user validity
    unless ($user) {
        Irssi::print("Error: no user specified. Syntax is /blowkeyx method nickname");
        return 1;
    }
    # remove the old key (if any)
    delete $channels{$user};
    # get pubkey, store header...
    my $pubkey = $dh1080->public_key;
    my $keyx_header="DH1080_INIT";
    # manipulate header for cbc if needed.
    if ($method eq 'cbc') {
        $keyx_header .= '_cbc';
        $keyx_cbc = 1;
    } else {
        $keyx_cbc = 0;
    }
    $server->command("\^NOTICE $user $keyx_header $pubkey");
    Irssi::print("KeyX started for $user using $method");
}

sub keyx_handler {
    my ($server, $message, $user) = @_;
    chomp $message;

    my ($command, $cbcflag, $peer_pubkey) = $message =~ /DH1080_(INIT|FINISH)(_cbc)? (.*)/i;
    return unless $command; # not for us

    unless ($peer_pubkey) {
        # (_cbc)? did not match, so $cbcflag is now really $peer_pubkey. fixing that:
        $peer_pubkey = $cbcflag;
        $cbcflag='';
    }
    if ($cbcflag eq '_cbc') {
        $keyx_cbc = 1;
    } else {
        $keyx_cbc = 0;
    }

    # need both these fro mhere
    return unless $command && $peer_pubkey;

    # handle it.
    my $secret = $dh1080->get_shared_secret($peer_pubkey);

    if ($secret) {
        if ($command =~ /INIT/i) {
            my $our_pubkey = $dh1080->public_key;
            my $keyx_header = 'DH1080_FINISH';
            if ($keyx_cbc == 1) {
                $keyx_header .= '_cbc';
            }
            $server->command("\^NOTICE $user $keyx_header $our_pubkey");
            Irssi::print("Received key from $user -- sent back our pubkey.");
        } else {
            Irssi::print("Negotiated key with $user");
        }
        if ($keyx_cbc == 1) {
            $secret = "cbc:$secret";
        }
        Irssi::print("Debug: key = $secret");
        $channels{$user} = 'keyx:'.$secret;

        # dont process this further
        Irssi::signal_stop();
    }
    else {
        Irssi::print("Error creating shared secret with $user");
    }

}

# This function generates random strings of a given length
sub generate_random_string {
    my $length_of_randomstring=shift; # the length of 
    # the random string to generate
    my @chars=('a'..'z','A'..'Z','0'..'9','_');
    my $random_string;
    foreach (1..$length_of_randomstring) {
        # rand @chars will generate a random 
        # number between 0 and scalar @chars
        $random_string.=$chars[rand @chars];
    }
    return $random_string;
}

sub send_text {
    my ($message, $server_rec, $witem) = @_;
    return unless ($message and $witem != 0 and $witem->{type} eq "CHANNEL");
    # if its dh1080_finish then skip encryption
    return if $message =~ /^DH1080_FINISH/;
    # otherwise process
    Irssi::signal_continue(encrypt_msg(t=>$witem->{name},m=>$message), $server_rec, $witem);
}

sub command_me {
    my ($message, $server_rec, $witem) = @_;
    my $channel = $witem->{name};
    Irssi::signal_continue(encrypt_msg(m=>$message, t=>$channel), $server_rec, $witem);
}
sub command_action {
    my ($args, $server_rec, $witem) = @_;
    my ($channel, $message) = split / /, $args, 2;
    my $text = encrypt_msg(m=>$message, t=>$channel);
    my $final_args = join " ", $channel, $text;
    Irssi::signal_continue(($final_args, $server_rec, $witem));
}

sub message_public {
    my ($server_rec, $msg, $nick, $addr, $channel) = @_;
    my $key = $channels{$channel};
    Irssi::signal_continue($server_rec, decrypt_msg(m=>$msg,t=>$channel), $nick, $addr, $channel);
}
sub message_own_public {
    my ($server_rec, $msg, $channel) = @_;
    Irssi::signal_continue($server_rec, decrypt_msg(m=>$msg,t=>$channel), $channel);
}

sub message_private {
    my ($server_rec, $msg, $nick, $addr) = @_;
    Irssi::signal_continue($server_rec, decrypt_msg(m=>$msg,t=>$nick), $nick, $addr);
}
sub message_own_private {
    my ($server_rec, $msg, $target, $orig_target) = @_;
    Irssi::signal_continue($server_rec, decrypt_msg(m=>$msg,t=>$target), $target, $orig_target);
}

sub command_topic {
    my ($args, $server_rec, $witem) = @_;
    my $channel = $witem->{name};
    Irssi::signal_continue("$channel ".encrypt_msg(t=>$channel,m=>$args), $server_rec, $witem);
}
sub message_topic {
    my ($server_rec, $channel, $topic, $nick, $address) = @_;
    Irssi::signal_continue($server_rec, $channel, decrypt_msg(t=>$channel,m=>$topic), $nick, $address);
}
sub event_topic {
    my ($server_rec, $args, $sender_nick, $sender_address) = @_;
    my ($nick, $channel, $topic) = split / +/, $args, 3;
    $topic = substr($topic, 1);
    my $text = decrypt_msg(t=>$channel, m=>$topic);
    Irssi::signal_continue($server_rec, "$nick $channel :$text", $sender_nick, $sender_address);
}

sub message_irc_action {
    my ($server_rec, $msg, $nick, $address, $target) = @_;
    Irssi::signal_continue($server_rec, decrypt_msg(t=>$target,m=>$msg), $nick, $address, $target);
}
sub message_irc_own_action {
    my ($server_rec, $msg, $target) = @_;
    Irssi::signal_continue($server_rec, decrypt_msg(m=>$msg,t=>$target), $target);
}

sub command_ctcp {
    my ($args, $server_rec, $witem) = @_;
    my $channel = $witem->{name};
    my ($target, $cmd, $data) = split / +/, $args, 3;
    my $text = encrypt_msg(t=>$target, m=>$data);
    Irssi::signal_continue("$target $cmd $text", $server_rec, $witem);
}
sub message_irc_ctcp {
    my ($server_rec, $cmd, $data, $nick, $address, $target) = @_;
    Irssi::signal_continue($server_rec, $cmd, decrypt_msg(m=>$data,t=>$target), $nick, $address, $target);
}
sub message_irc_own_ctcp {
    my ($server_rec, $cmd, $data, $target) = @_;
    Irssi::signal_continue($server_rec, $cmd, decrypt_msg(m=>$data,t=>$target), $target);
}

sub topic {
    my ($server, $msg) = @_;
    my ($nick, $channel) = $msg =~ /^([^\s]+)\s+([^\s]+)/;
    my ($topic) = $msg =~ /:(.*)/;

    my $key = $channels{$channel};

    if (!$key) {
        return;
    } else {
        my $text = decrypt_msg(t=>$channel, m=>$topic);
        Irssi::signal_continue(($server, "$nick $channel :$text"));
    }
}

sub encrypt_msg {
    my %args = @_;

    my $message = $args{m};
    my $target = $args{t};
    my $key = $channels{$target};

    return $message unless Irssi::settings_get_bool("docrypt");  # disabled
    return $message unless $key && $message;  # no key

    return substr($message, 1) if $message =~ /^`/;  # want plain

    $key = substr($key, 5) if ($key =~ /^keyx:/);

    # check if we're doing cbc or not
    my $method = 'unknown';
    if ($key =~ /^cbc:/) {
        # encrypt using cbc
        $key = blowkey(substr($key, 4));
        my $randomiv = generate_random_string(8);
        my $cipher = Crypt::CBC->new(
            -key => $key,
            -cipher => 'Blowfish',
            -header => 'none',
            -literal_key => 0,
            -iv => $randomiv,
            -padding => 'null',
            -keysize => 56
        );
        $cipher->{literal_key} = 1; # hack around Crypt:CBC limitation/bug

        # my $cbc = $cipher->encrypt($randomiv . $message);
        my $cbc = $randomiv . $cipher->encrypt($message);

        return $prefixes[0] . '*' . encode_base64($cbc);
    } else {
        # set key
        $blowfish->set_key($key);
        # encrypt using blowfish
        return $prefixes[0] . $blowfish->encrypt($message);
    }
}

sub decrypt_msg {
    my %args = @_;

    my $message = $args{m};
    my $target = $args{t};
    my $key = $channels{$target};

    return $message unless Irssi::settings_get_bool("docrypt");
    return $message unless $message && $key;

    chomp $message;

    $key = substr($key, 5) if $key =~ /^keyx:/;  # cut the keyx prefix

    # check for prefix
    my $found_prefix = 0;
    foreach my $prefix (@prefixes) {
        my $ppfix = substr $message, 0, length($prefix);
        if ($ppfix eq $prefix) {
            # remove prefix
            $message = substr $message, length($prefix);
            $found_prefix = 1;
            last;
        }
    }

    # skip encryption if the message isn't prefixed with an encryption trigger.
    unless ($found_prefix) {
        $message = Irssi::settings_get_str("mark_string") . $message if Irssi::settings_get_bool("mark_unencrypted");
        return $message;
    }

    my $result;
    # detect encryption type...
    if ($key =~ '^cbc:') {
        # decrypt with cbc
        $key = substr($key, 4);  # get rid of "cbc:" from key

        # remove the asterisk from data
        $message = substr($message, 1);

        # base64 decode the rest
        $message = decode_base64($message);

        # get the IV (first 8 bytes) and remove it from data;
        my $randomiv = substr($message, 0, 8);
        $message = substr($message, 8);

        # make sure key > 8 bytes.
        $key = blowkey($key);

        my $cipher = Crypt::CBC->new( -key => $key,
                                      -cipher => 'Blowfish',
                                      -header => 'none',
                                      -literal_key => 0,
                                      -padding => 'null',
                                      -iv => $randomiv
                                  );
        $cipher->{literal_key} = 1; # hack around Crypt::CBC limitation/bug
        $result = $cipher->decrypt($message);
    } else {
        # decrypt with blowfish
        $blowfish->set_key($key);
        $result = $blowfish->decrypt($message);
    }

    chomp $result;

    return $result;
}

# dcc proxy function because params for dcc messages are different
sub dcc {
    my ($server, $data) = @_ ;
    encrypt($server,$data,$server->{nick},undef);
}

# load config
loadconf();

# inform user of stuff
Irssi::print("blowssi script $VERSION loaded\n");

Irssi::settings_add_bool('blowssi', 'mark_unencrypted' => 1);
Irssi::settings_add_str("blowssi", "mark_string" => "[u] ");
Irssi::settings_add_bool("blowssi", "docrypt" => 1);

# register irssi commands
Irssi::command_bind("blowon","blowon");
Irssi::command_bind("blowoff","blowoff");
Irssi::command_bind("blowkey","setkey");
Irssi::command_bind("blowdel","delkey");
Irssi::command_bind("blowkeyx", "keyx");
Irssi::command_bind("blowhelp", "blowhelp");

Irssi::signal_add_first("command msg", "command_action"); # ok
Irssi::signal_add_first("command me", "command_me"); # ok
Irssi::signal_add_first("command action", "command_action"); # ok
Irssi::signal_add_first("command notice", "command_action"); # notice and action are the same

#Irssi::signal_add_first("event topic", "topic");
Irssi::signal_add_first("event 331", "event_topic"); # OK
Irssi::signal_add_first("event 332", "event_topic"); # OK

Irssi::signal_add_first("send text", "send_text");  # OK
Irssi::signal_add_first("message public", "message_public"); #OK
Irssi::signal_add_first("message own_public", "message_own_public"); # OK
Irssi::signal_add_first("message private", "message_private");
Irssi::signal_add_first("message own_private", "message_own_private");
Irssi::signal_add_first("message irc action", "message_irc_action"); # OK
Irssi::signal_add_first("message irc notice", "message_irc_action"); # OK
Irssi::signal_add_first("message irc own_action", "message_irc_own_action"); # OK
Irssi::signal_add_first("message irc own_notice", "message_irc_own_action"); # OK

#Irssi::signal_add_first("command ctcp", "command_ctcp"); # OK
#Irssi::signal_add_first("message irc ctcp", "message_irc_ctcp"); # Not OK, need lower level processing.
#Irssi::signal_add_first("message irc own_ctcp", "message_irc_own_ctcp"); # OK

Irssi::signal_add_first("command topic", "command_topic");
Irssi::signal_add_first("message topic", "message_topic");

# dh1080 handling
Irssi::signal_add_first("message irc notice", "keyx_handler");


