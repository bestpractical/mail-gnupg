# -*- perl -*-

use Test::More;
use Mail::GnuPG;
use MIME::Entity;
use strict;

plan tests => 5;

# Main program
my $parser = new MIME::Parser;
$parser->output_to_core(1);
$parser->decode_bodies(0);

my $entity= $parser->parse_open("t/msg/multipart-signed-qp.eml") ;
isa_ok($entity,"MIME::Entity");

my $mg = new Mail::GnuPG( key => '49539D60EFEA4EAD',
			  passphrase => 'passphrase');

isa_ok($mg,"Mail::GnuPG");

my ($return,$keyid,$uid) = $mg->verify($entity);
is($return,0,"verify success");
is($keyid,'9456D16A',"verify keyid");
is($uid,'Mauricio Campiglia <mauricio@campiglia.org>',"verify uid");

end:
