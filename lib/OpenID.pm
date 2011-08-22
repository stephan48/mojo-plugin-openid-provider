package OpenID;

use Mojo::Base -base;
use Math::BigInt;
use MIME::Base64;

sub _rand_chars {
    shift if @_ == 2;  # shift off classname/obj, if called as method
    my $length = shift;

    my $chal = "";
    my $digits = "abcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWZYZ0123456789";

    for (1..$length) {
        $chal .= substr($digits, int(rand(62)), 1);
    }

    return $chal;
}

sub _secret_of_handle {
    my $self = shift;
    my ($handle, %opts) = @_;

    my $dumb_mode = delete $opts{'dumb'}      || 0;
    my $no_verify = delete $opts{'no_verify'} || 0;
    my $type = delete $opts{'type'} || 'HMAC-SHA1';
    my %hmac_functions_hex=(
                   'HMAC-SHA1'  =>\&hmac_sha1_hex,
                   'HMAC-SHA256'=>\&hmac_sha256_hex,
                  );
    my %hmac_functions=(
                   'HMAC-SHA1'  =>\&hmac_sha1,
                   'HMAC-SHA256'=>\&hmac_sha256,
                  );
    my %nonce_80_lengths=(
                          'HMAC-SHA1'=>10,
                          'HMAC-SHA256'=>16,
                         );
    my $nonce_80_len=$nonce_80_lengths{$type};
    my $hmac_function_hex=$hmac_functions_hex{$type} || Carp::croak "No function for $type";
    my $hmac_function=$hmac_functions{$type} || Carp::croak "No function for $type";
    Carp::croak("Unknown options: " . join(", ", keys %opts)) if %opts;

    my ($time, $nonce, $nonce_sig80) = split(/:/, $handle);
    return unless $time =~ /^\d+$/ && $nonce && $nonce_sig80;

    # check_authentication mode only verifies signatures made with
    # dumb (stateless == STLS) handles, so if that caller requests it,
    # don't return the secrets here of non-stateless handles
    return if $dumb_mode && $nonce !~ /^STLS\./;

    my $sec_time = $time - ($time % $self->secret_gen_interval);
    my $s_sec = $self->_get_server_secret($sec_time)  or return;

    length($nonce)       == ($dumb_mode ? 25 : 20) or return;
    length($nonce_sig80) == $nonce_80_len          or return;

    return unless $no_verify || $nonce_sig80 eq substr($hmac_function_hex->("$time:$nonce", $s_sec), 0, $nonce_80_len);

    return $hmac_function->($handle, $s_sec);
}

sub _time_to_w3c {
    my $self = shift;
    my $time = shift || time();
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = gmtime($time);
    $mon++;
    $year += 1900;

    return sprintf("%04d-%02d-%02dT%02d:%02d:%02dZ", $year, $mon, $mday, $hour, $min, $sec);
};

sub hash_to_kv {
  my ($self, $hash) = @_;
  my $output;
  $output = join(
    "\n",
        map( sprintf( q{%s:%s}, $_, $hash->{$_} ),
            sort keys %{ $hash } )
    )."\n";
  return $output;
}

sub _b64 {
    my $val = MIME::Base64::encode_base64($_[0]);
    $val =~ s/\s+//g;
    return $val;
}

sub _bi2bytes {
    my $bigint = shift;
    die "Can't deal with negative numbers" if $bigint->is_negative;

    my $bits = $bigint->as_bin;
    die unless $bits =~ s/^0b//;

    # prepend zeros to round to byte boundary, or to unset high bit
    my $prepend = (8 - length($bits) % 8) || ($bits =~ /^1/ ? 8 : 0);
    $bits = ("0" x $prepend) . $bits if $prepend;

    return pack("B*", $bits);
}

sub _bi2arg {
    return _b64(_bi2bytes($_[0]));
}

sub _bytes2bi {
    return Math::BigInt->new("0b" . unpack("B*", $_[0]));
}

sub _arg2bi {
    return undef unless defined $_[0] && $_[0] ne "";
    # don't acccept base-64 encoded numbers over 700 bytes.  which means
    # those over 4200 bits.
    return Math::BigInt->new("0") if length($_[0]) > 700;
    return _bytes2bi(MIME::Base64::decode_base64($_[0]));
}


1;
