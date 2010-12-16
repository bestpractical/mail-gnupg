# -*- perl -*-

use Test::More;
use File::Temp qw(tempdir);
use Mail::GnuPG;
use MIME::Entity;
use strict;

my $FULL_KEY = "49539D60EFEA4EAD";
my $KEY = substr($FULL_KEY,-8,8);

my $WHO = "Mail::GnuPG Test Key <mail\@gnupg.dom>";

require('t/import_keys.pl');
my $gpghome=import_keys('t/test-key.pgp',$FULL_KEY);
unless (defined($gpghome)){
  plan skip_all => "failed to import GPG keys for testing";
  goto end;
}

plan tests => 20;


my $mg = new Mail::GnuPG( key => '49539D60EFEA4EAD',
			  keydir => $gpghome,
			  passphrase => 'passphrase');

isa_ok($mg,"Mail::GnuPG");

my $line = "x\n";
my $string = $line x 100000;

my $copy;
my $me =  MIME::Entity->build(From    => 'me@myhost.com',
			      To      => 'you@yourhost.com',
			      Subject => "Hello, nurse!",
			      Data    => [$string]);
# Test MIME Signing Round Trip

$copy = $me->dup;

is( 0, $mg->mime_sign( $copy ) );

my ($verify,$key,$who) = $mg->verify($copy);
is( 0, $verify );
is( $KEY, $key );
is( $WHO, $who );

is( 1, $mg->is_signed($copy) );
is( 0, $mg->is_encrypted($copy) );

# Test Clear Signing Round Trip

$copy = $me->dup;

is( 0, $mg->clear_sign( $copy ) );

{ my ($verify,$key,$who) = $mg->verify($copy);
is( 0, $verify );
is( $KEY, $key );
is( $WHO, $who );

is( 1, $mg->is_signed($copy) );
is( 0, $mg->is_encrypted($copy) );
}
# Test MIME Encryption Round Trip

$copy = $me->dup;

is( 0, $mg->ascii_encrypt( $copy, $KEY ));
is( 0, $mg->is_signed($copy) );
is( 1, $mg->is_encrypted($copy) );

($verify,$key,$who) = $mg->decrypt($copy);

is( 0, $verify );
is( undef, $key );
is( undef, $who );

is_deeply($mg->{decrypted}->body,$me->body);

end:
