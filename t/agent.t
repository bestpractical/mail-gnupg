# -*- perl -*-

use Test::More;
use File::Temp qw(tempdir);
use Mail::GnuPG;
use MIME::Entity;
use strict;
no warnings 'redefine';         # fix this later

my $KEY = "EFEA4EAD"; # 49539D60EFEA4EAD
my $WHO = "Mail::GnuPG Test Key <mail\@gnupg.dom>";

unless ( 0 == system("gpg --version 2>&1 >/dev/null") &&
       0 == system("gpg-agent --version 2>&1 >/dev/null")) {
  plan skip_all => "gpg, gpg-agent in path required for testing agent";
  goto end;
}

my $preset=$ENV{GPG_PRESET_PASSPHRASE} || "/usr/lib/gnupg2/gpg-preset-passphrase";

unless (0 == system("$preset --version 2>&1 >/dev/null")) {
  plan skip_all => "gpg-preset-passphrase not found; set GPG_PRESET_PASSPHRASE in environment to location of binary";
  goto end;
}

my $tmpdir = tempdir( "mgtXXXXX", CLEANUP => 1);

unless ( 0 == system("gpg --homedir $tmpdir --trusted-key 0x49539D60EFEA4EAD --import t/test-key.pgp 2>&1 >/dev/null")) {
  plan skip_all => "unable to import testing keys";
  goto end;
}

unless (open AGENT, "gpg-agent  --disable-scdaemon --allow-preset --daemon|") {
  plan skip_all =>"unable to start gpg-agent";
  goto end;
}

my ($agent_pid,$agent_info);
while (<AGENT>){
  if (m/GPG_AGENT_INFO=([^;]*);/){
    $agent_info=$1;
    $ENV{'GPG_AGENT_INFO'}=$agent_info;
    my @parts=split(':',$agent_info);
    $agent_pid=$parts[1];
  }
}

# gpg-preset-passphrase uses the fingerprint of the subkey, rather than the id.
unless ( 0 == system ("$preset --preset -P passphrase " .
		      "576AE2D0BC6974C083705EE033A736779FE08E94") 
	 && 0 == system ("$preset --preset -P passphrase " .
		      "8E136E6F34C0D4CD941A9DB749539D60EFEA4EAD")    ){
  plan skip_all =>"unable to cache passphrase";
  goto end;
}

plan tests => 20;


my $mg = new Mail::GnuPG( key => '49539D60EFEA4EAD',
			  keydir => $tmpdir,
			  use_agent => 1);

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
kill 15,$agent_pid if (defined($agent_pid));


