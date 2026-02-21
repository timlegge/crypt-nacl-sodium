use strict;
use warnings;
use Test::More;


use Crypt::NaCl::Sodium qw( :utils );

my $crypto_generichash = Crypt::NaCl::Sodium->generichash();
#
# generate secret key
my $key = '1' x $crypto_generichash->KEYBYTES;

my $data = "The quick brown fox jumps over the lazy dog";
my $s1 = $crypto_generichash->mac($data, key => $key);
my $stream = $crypto_generichash->init(key => $key);
$stream->update(substr($data, 0, 10));
$stream->update(substr($data, 10));
my $s2 = $stream->final();
ok($s1->to_hex eq $s2->to_hex, "streams match");
die "API FAILURE" if $s1->to_hex ne $s2->to_hex;

done_testing();

