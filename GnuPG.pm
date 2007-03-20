package Mail::GnuPG;

=head1 NAME

Mail::GnuPG - Process email with GPG.

=head1 SYNOPSIS

  use Mail::GnuPG;
  my $mg = new Mail::GnuPG( key => 'ABCDEFGH' );
  $ret = $mg->mime_sign( $MIMEObj, 'you@my.dom' );

=head1 DESCRIPTION

Use GnuPG::Interface to process or create PGP signed or encrypted
email.

=cut

use 5.006;
use strict;
use warnings;

our $VERSION = '0.07';

use GnuPG::Interface;
use File::Temp;
use IO::Handle;
use MIME::Entity;
use MIME::Parser;
use Mail::Address;

=head2 new

  Create a new Mail::GnuPG instance.

 Arguments:
   Paramhash...

   key    => gpg key id
   keydir => gpg configuration/key directory
   passphrase => primary key password

   # FIXME: we need more things here, maybe primary key id.


=cut

sub new {
  my $proto = shift;
  my $class = ref($proto) || $proto;
  my $self  = {
	       key	    => undef,
	       keydir	    => undef,
	       passphrase   => "",
	       gpg_path	    => "gpg",
	       @_
	      };
  $self->{last_message} = [];
  $self->{plaintext} = [];
  bless ($self, $class);
  return $self;
}

sub _set_options {
  my ($self,$gnupg) = @_;
  $gnupg->options->meta_interactive( 0 );
  $gnupg->options->hash_init( armor   => 1,
			      ( defined $self->{keydir} ?
				(homedir => $self->{keydir}) : () ),
			      ( defined $self->{key} ?
				( default_key => $self->{key} ) : () ),
#			      ( defined $self->{passphrase} ?
#				( passphrase => $self->{passphrase} ) : () ),
			    );
  $gnupg->call( $self->{gpg_path} ) if defined $self->{gpg_path};
}


=head2 decrypt

 Decrypt an encrypted message

 Input:
   MIME::Entity containing email message to decrypt.

  The message can either be in RFC compliant-ish multipart/encrypted
  format, or just a single part ascii armored message.

 Output:
  Exit code of gpg.  (0 on success)

  $self->{last_message} => any errors from gpg
  $self->{plaintext}    => plaintext output from gpg
  $self->{decrypted}    => parsed output as MIME::Entity

=cut

sub decrypt {
  my ($self, $message) = @_;
  my $ciphertext = "";

  $self->{last_message} = [];

  unless (ref $message && $message->isa("MIME::Entity")) {
    die "decrypt only knows about MIME::Entitys right now";
    return 255;
  }

  my $armor_message = 0;
  if ($message->effective_type =~ m!multipart/encrypted!) {
    die "multipart/encrypted with more than two parts"
      if ($message->parts != 2);
    die "Content-Type not pgp-encrypted"
      unless $message->parts(0)->effective_type =~
	m!application/pgp-encrypted!;
    $ciphertext = $message->parts(1)->stringify_body;
  }
  elsif ($message->body_as_string
	 =~ m!^-----BEGIN PGP MESSAGE-----!m ) {
    $ciphertext = $message->body_as_string;
    $armor_message = 1;
  }
  else {
    die "Unknown Content-Type or no PGP message in body"
  }

  my $gnupg = GnuPG::Interface->new();
  $self->_set_options($gnupg);
  # how we create some handles to interact with GnuPG
  # This time we'll catch the standard error for our perusing
  # as well as passing in the passphrase manually
  # as well as the status information given by GnuPG
  my ( $input, $output, $error, $passphrase_fh, $status_fh )
    = ( new IO::Handle, new IO::Handle,new IO::Handle,
	new IO::Handle,new IO::Handle,);

  my $handles = GnuPG::Handles->new( stdin      => $input,
				     stdout     => $output,
				     stderr     => $error,
				     passphrase => $passphrase_fh,
				     status     => $status_fh,
				   );

  # this sets up the communication
  my $pid = $gnupg->decrypt( handles => $handles );

  # This passes in the passphrase
  die "NO PASSPHRASE" unless defined $passphrase_fh;
  print $passphrase_fh $self->{passphrase};
  close $passphrase_fh;

  # this passes in the plaintext
  print $input $ciphertext;

  # this closes the communication channel,
  # indicating we are done
  close $input;

  my @plaintext    = <$output>;   # reading the output
  my @error_output = <$error>;    # reading the error
  my @status_info  = <$status_fh>;# read the status info

  # clean up...
  close $output;
  close $error;
  close $status_fh;

  waitpid $pid, 0;  # clean up the finished GnuPG process
  my $exit_value  = $? >> 8;

  $self->{last_message} = \@error_output;
  $self->{plaintext}    = \@plaintext;

  my $parser = new MIME::Parser;
  $parser->output_to_core(1);

  # for armor message (which usually contain no MIME entity)
  # and if the first line seems to be no header, add an empty
  # line at the top, otherwise the first line of a text message
  # will be removed by the parser.
  if ( $armor_message and $plaintext[0] and $plaintext[0] !~ /^[\w-]+:/ ) {
    unshift @plaintext, "\n";
  }

  my $entity = $parser->parse_data(\@plaintext);
  $self->{decrypted} = $entity;

  return $exit_value;
}

=head2 get_decrypt_key

 determines the decryption key (and corresponding mail) of a message

 Input:
   MIME::Entity containing email message to analyze.

  The message can either be in RFC compliant-ish multipart/signed
  format, or just a single part ascii armored message.

 Output:
  $key    -- decryption key
  $mail   -- corresponding mail address

=cut

sub get_decrypt_key {
  my ($self, $message) = @_;

  unless (ref $message && $message->isa("MIME::Entity")) {
    die "decrypt only knows about MIME::Entitys right now";
  }

  my $ciphertext;

  if ($message->effective_type =~ m!multipart/encrypted!) {
    die "multipart/encrypted with more than two parts"
      if ($message->parts != 2);
    die "Content-Type not pgp-encrypted"
      unless $message->parts(0)->effective_type =~
	m!application/pgp-encrypted!;
    $ciphertext = $message->parts(1)->stringify_body;
  }
  elsif ($message->body_as_string
	 =~ m!^-----BEGIN PGP MESSAGE-----!m ) {
    $ciphertext = $message->body_as_string;
  }
  else {
    die "Unknown Content-Type or no PGP message in body"
  }

  my $gnupg = GnuPG::Interface->new();

  # how we create some handles to interact with GnuPG
  # This time we'll catch the standard error for our perusing
  # as well as passing in the passphrase manually
  # as well as the status information given by GnuPG
  my ( $input, $output, $stderr )
    = ( new IO::Handle, new IO::Handle, new IO::Handle );

  my $handles = GnuPG::Handles->new( stdin      => $input,
				     stdout     => $output,
				     stderr     => $stderr,
				   );

  # this sets up the communication
  my $pid = $gnupg->wrap_call(
  	handles      => $handles,
  	commands     => [ "--decrypt" ],
	command_args => [ "--batch", "--list-only", "--status-fd", "1" ],
  );

  # this passes in the ciphertext
  print $input $ciphertext;

  # this closes the communication channel,
  # indicating we are done
  close $input;

  # reading the output
  my @result = <$output>;

  # clean up...
  close $output;

  # clean up the finished GnuPG process
  waitpid $pid, 0;
  my $exit_value  = $? >> 8;

  # set last_message
  $self->{last_message} = \@result;

  # grep ENC_TO and NO_SECKEY items
  my (@enc_to_keys, %no_sec_keys);
  for ( @result ) {
  	push @enc_to_keys, $1 if /ENC_TO\s+([^\s]+)/;
	$no_sec_keys{$1} = 1  if /NO_SECKEY\s+([^\s]+)/;
  }

  # find first key we have the secret portion of
  my $key;
  foreach my $k ( @enc_to_keys ) {
  	if ( not exists $no_sec_keys{$k} ) {
	  	$key = $k;
		last;
	}
  }

  return if not $key;

  # get mail address of this key
  my $gpg_out = qx[ gpg --with-colons --list-keys $key 2>&1 ];
  die "Couldn't find key $key in keyring" if $gpg_out !~ /\S/ or $?;
  my $mail = (split(":", $gpg_out))[9];

  return ($mail, $key);
}

=head2 verify

 verify a signed message

 Input:
   MIME::Entity containing email message to verify.

  The message can either be in RFC compliant-ish multipart/signed
  format, or just a single part ascii armored message.

 Output:
  On error:
    Exit code of gpg.  (0 on success)
  On success
    ( 0,
      keyid,           # ABCDDCBA
      emailaddress     # Foo Bar <foo@bar.com>
    )

   where the keyid is the key that signed it, and emailaddress is full
   name and email address of the primary uid

  $self->{last_message} => any errors from gpg

=cut

# Verify RFC2015/RFC3156 email
sub verify {
  my ($self, $message) = @_;

  my $ciphertext = "";
  my $sigtext    = "";

  $self->{last_message} = [];

  unless (ref $message && $message->isa("MIME::Entity")) {
    die "VerifyMessage only knows about MIME::Entitys right now";
    return 255;
  }

  if ($message->effective_type =~ m!multipart/signed!) {
    die "multipart/signed with more than two parts"
      if ($message->parts != 2);
    die "Content-Type not pgp-signed"
      unless $message->parts(1)->effective_type =~
	m!application/pgp-signature!;
    $ciphertext = $message->parts(0)->as_string;
    $sigtext    = $message->parts(1)->stringify_body;
  }
  elsif ( $message->bodyhandle and $message->bodyhandle->as_string
	 =~ m!^-----BEGIN PGP SIGNED MESSAGE-----!m ) {
    # don't use not $message->body_as_string here, because
    # the body isn't decoded in this case!!!
    # (which is evil for quoted-printable transfer encoding)
    # also the headers and stuff are not needed here
    $ciphertext = undef;
    $sigtext    = $message->bodyhandle->as_string; # well, actually both
  }
  else {
    die "Unknown Content-Type or no PGP message in body"
  }

  my $gnupg = GnuPG::Interface->new();
  $self->_set_options($gnupg);
  # how we create some handles to interact with GnuPG
  my $input   = IO::Handle->new();
  my $error   = IO::Handle->new();
  my $handles = GnuPG::Handles->new( stderr => $error, stdin  => $input );

  my ($sigfh, $sigfile)
    = File::Temp::tempfile('mgsXXXXXXXX',
			   UNLINK => 1,
			  );
  print $sigfh $sigtext;
  close($sigfh);

  my ($datafh, $datafile) =
    File::Temp::tempfile('mgdXXXXXX',
			 UNLINK => 1,
			);

  # according to RFC3156 all line endings MUST be CR/LF
  if ( defined $ciphertext ) {
    $ciphertext =~ s/\x0A/\x0D\x0A/g;
    $ciphertext =~ s/\x0D+/\x0D/g;
  }

  # Read the (unencoded) body data:
  # as_string includes the header portion
  print $datafh $ciphertext if $ciphertext;
  close($datafh);

  my $pid = $gnupg->verify( handles => $handles,
			    command_args => ( $ciphertext ?
					      ["$sigfile", "$datafile"] :
					      "$sigfile" ),
			  );

  # Now we write to the input of GnuPG
  # now we read the output
  my @result = <$error>;
  close $error;
  close $input;

  unlink $sigfile, $datafile;

  waitpid $pid, 0;
  my $exit_value  = $? >> 8;

  $self->{last_message} = [@result];

  return $exit_value if $exit_value; # failure

  # FIXME: these regex are likely to break under non english locales.
  my $result = join "", @result;
  my ($keyid)  = $result =~ /using \S+ key ID (.+)$/m;
  my ($pemail) = $result =~ /Good signature from "(.+)"$/m;

  return ($exit_value,$keyid,$pemail);

}

# Should this go elsewhere?  The Key handling stuff doesn't seem to
# make sense in a Mail:: module.  
my %key_cache;
my $key_cache_age = 0;
my $key_cache_expire = 60*60*30; # 30 minutes

sub _rebuild_key_cache {
  my $self = shift;
  local $_;
  %key_cache = ();
  # sometimes the best tool for the job... is not perl
  open(my $fh, "$self->{gpg_path} --list-public-keys --with-colons | cut -d: -f10|")
    or die $!;
  while(<$fh>) {
    next unless $_;
    # M::A may not parse the gpg stuff properly.  Cross fingers
    my ($a) = Mail::Address->parse($_); # list context, please
    $key_cache{$a->address}=1 if ref $a;
  }
}

=head2 has_public_key

Does the keyring have a public key for the specified email address? 

 FIXME: document better.  talk about caching.  maybe put a better
 interface in.

=cut


sub has_public_key {
  my ($self,$address) = @_;

  # cache aging is disabled until someone has enough time to test this
  if (0) {
    $self->_rebuild_key_cache() unless ($key_cache_age);

    if ( $key_cache_age && ( time() - $key_cache_expire > $key_cache_age )) {
      $self->_rebuild_key_cache();
    }
  }

  $self->_rebuild_key_cache();

  return 1 if exists $key_cache{$address};
  return 0;

}

=head2 mime_sign

  sign an email message

 Input:
   MIME::Entity containing email message to sign

 Output:
  Exit code of gpg.  (0 on success)

  $self->{last_message} => any errors from gpg

  The provided $entity will be signed.  (i.e. it _will_ be modified.)

=cut


sub mime_sign {
  my ($self,$entity) = @_;

  die "Not a mime entity"
    unless $entity->isa("MIME::Entity");

  $entity->make_multipart;
  my $workingentity = $entity;
  if ($entity->parts > 1) {
    $workingentity = MIME::Entity->build(Type     => "multipart/mixed");
    $workingentity->add_part($_) for ($entity->parts);
    $entity->parts([]);
    $entity->add_part($workingentity);
  }

  my $gnupg = GnuPG::Interface->new();
  $self->_set_options( $gnupg );
  my ( $input, $output, $error, $passphrase_fh, $status_fh )
    = ( new IO::Handle, new IO::Handle,new IO::Handle,
	new IO::Handle,new IO::Handle,);
  my $handles = GnuPG::Handles->new( stdin      => $input,
				     stdout     => $output,
				     stderr     => $error,
				     passphrase => $passphrase_fh,
				     status     => $status_fh,
				   );
  my $pid = $gnupg->detach_sign( handles => $handles );
  die "NO PASSPHRASE" unless defined $passphrase_fh;
  print $passphrase_fh $self->{passphrase};
  close $passphrase_fh;


  # this passes in the plaintext
  my $plaintext;
  if ($workingentity eq $entity) {
#    $RT::Logger->crit("SINGLEPART");
    $plaintext = $entity->parts(0)->as_string;
  } else {
    $plaintext = $workingentity->as_string;
  }

  # according to RFC3156 all line endings MUST be CR/LF
  $plaintext =~ s/\x0A/\x0D\x0A/g;
  $plaintext =~ s/\x0D+/\x0D/g;

  # should we store this back into the body?
  print $input $plaintext;

  # DEBUG:
#  print "SIGNING THIS STRING ----->\n";
#  $plaintext =~ s/\n/-\n/gs;
#  $RT::Logger->crit("SIGNING:\n$plaintext<<<");
#  $RT::Logger->crit($entity->as_string);
#  print STDERR $plaintext;
#  print "<----\n";
  $input->flush();
  $input->sync();
  close $input;

  my @signature    = <$output>;   # reading the output
  my @error_output = <$error>;    # reading the error
  my @status_info  = <$status_fh>;# read the status info

  # clean up...
  close $output;
  close $error;
  close $status_fh;

  waitpid $pid, 0;  # clean up the finished GnuPG process
  my $exit_value  = $? >> 8;

  $self->{last_message} = \@error_output;

  $entity->attach( Type => "application/pgp-signature",
		   Disposition => "inline",
		   Data => [@signature],
		   Encoding => "7bit");

  $entity->head->mime_attr("Content-Type","multipart/signed");
  $entity->head->mime_attr("Content-Type.protocol","application/pgp-signature");
#  $entity->head->mime_attr("Content-Type.micalg","pgp-md5");

  return $exit_value;
}

=head2 clear_sign

  clearsign the body of an email message

 Input:
   MIME::Entity containing email message to sign.
   This entity MUST have a body.

 Output:
  Exit code of gpg.  (0 on success)

  $self->{last_message} => any errors from gpg

  The provided $entity will be signed.  (i.e. it _will_ be modified.)

=cut

sub clear_sign {
  my ($self, $entity) = @_;
  
  die "Not a mime entity"
    unless $entity->isa("MIME::Entity");

  my $body = $entity->bodyhandle;
  
  die "Message has no body"
    unless defined $body;

  my $gnupg = GnuPG::Interface->new();
  $self->_set_options( $gnupg );
  $gnupg->passphrase ( $self->{passphrase} );

  my ( $input, $output, $error )
    = ( new IO::Handle, new IO::Handle, new IO::Handle);

  my $handles = GnuPG::Handles->new(
  	stdin	=> $input,
	stdout	=> $output,
	stderr	=> $error,
  );

  my $pid = $gnupg->clearsign ( handles => $handles );

  my $plaintext = $body->as_string;

  $plaintext =~ s/\x0A/\x0D\x0A/g;
  $plaintext =~ s/\x0D+/\x0D/g;

  print $input $plaintext;
  close $input;
  
  my @ciphertext = <$output>;
  my @error_output = <$error>;
  
  close $output;
  close $error;

  waitpid $pid, 0;
  my $exit_value  = $? >> 8;

  $self->{last_message} = [@error_output];

  my $io = $body->open ("w") or die "can't open entity body";
  $io->print (join('',@ciphertext));
  $io->close;

  return $exit_value;
}


=head2 ascii_encrypt

  encrypt an email message body using ascii armor

 Input:
   MIME::Entity containing email message to encrypt.
   This entity MUST have a body.

   list of recipients

 Output:
  Exit code of gpg.  (0 on success)

  $self->{last_message} => any errors from gpg

  The provided $entity will be encrypted.  (i.e. it _will_ be modified.)

=head2 ascii_signencrypt

  encrypt and sign an email message body using ascii armor

 Input:
   MIME::Entity containing email message to encrypt.
   This entity MUST have a body.

   list of recipients

 Output:
  Exit code of gpg.  (0 on success)

  $self->{last_message} => any errors from gpg

  The provided $entity will be encrypted.  (i.e. it _will_ be modified.)

=cut

sub ascii_encrypt {
  my ($self, $entity, @recipients) = @_;
  $self->_ascii_encrypt($entity, 0, @recipients);
}

sub ascii_signencrypt {
  my ($self, $entity, @recipients) = @_;
  $self->_ascii_encrypt($entity, 1, @recipients);
}

sub _ascii_encrypt {
  my ($self, $entity, $sign, @recipients) = @_;
  
  die "Not a mime entity"
    unless $entity->isa("MIME::Entity");

  my $body = $entity->bodyhandle;
  
  die "Message has no body"
    unless defined $body;

  my $plaintext = $body->as_string;

  my $gnupg = GnuPG::Interface->new();
  $self->_set_options( $gnupg );
  $gnupg->passphrase ( $self->{passphrase} );
  $gnupg->options->push_recipients( $_ ) for @recipients;

  my ( $input, $output, $error )
    = ( new IO::Handle, new IO::Handle, new IO::Handle);

  my $handles = GnuPG::Handles->new(
  	stdin	=> $input,
	stdout	=> $output,
	stderr	=> $error,
  );

  my $pid = do {
  	if ( $sign ) {
		$gnupg->sign_and_encrypt ( handles => $handles );
	} else {
		$gnupg->encrypt ( handles => $handles );
	}
  };

  print $input $plaintext;
  close $input;
  
  my @ciphertext = <$output>;
  my @error_output = <$error>;
  
  close $output;
  close $error;

  waitpid $pid, 0;
  my $exit_value  = $? >> 8;

  $self->{last_message} = [@error_output];

  my $io = $body->open ("w") or die "can't open entity body";
  $io->print (join('',@ciphertext));
  $io->close;

  return $exit_value;
}

=head2 mime_encrypt

  encrypt an email message

 Input:
   MIME::Entity containing email message to encrypt
   list of email addresses to sign to

 Output:
  Exit code of gpg.  (0 on success)

  $self->{last_message} => any errors from gpg

  The provided $entity will be encrypted.  (i.e. it _will_ be modified.)

=head2 mime_signencrypt

  sign and encrypt an email message

 Input:
   MIME::Entity containing email message to sign encrypt
   list of email addresses to sign to

 Output:
  Exit code of gpg.  (0 on success)

  $self->{last_message} => any errors from gpg

  The provided $entity will be encrypted.  (i.e. it _will_ be modified.)

=cut

sub mime_encrypt {
  my $self = shift;
  $self->_mime_encrypt(0,@_);
}

sub mime_signencrypt {
  my $self = shift;
  $self->_mime_encrypt(1,@_);
}

sub _mime_encrypt {
  my ($self,$sign,$entity,@recipients) = @_;

  die "Not a mime entity"
    unless $entity->isa("MIME::Entity");

  my $workingentity = $entity;
  $entity->make_multipart;
  if ($entity->parts > 1) {
    $workingentity = MIME::Entity->build(Type     => "multipart/mixed");
    $workingentity->add_part($_) for ($entity->parts);
    $entity->parts([]);
    $entity->add_part($workingentity);
  }

  my $gnupg = GnuPG::Interface->new();

  $gnupg->options->push_recipients( $_ ) for @recipients;
  $self->_set_options($gnupg);
  my ( $input, $output, $error, $passphrase_fh, $status_fh )
    = ( new IO::Handle, new IO::Handle,new IO::Handle,
	new IO::Handle,new IO::Handle,);
  my $handles = GnuPG::Handles->new( stdin      => $input,
				     stdout     => $output,
				     stderr     => $error,
				     passphrase => $passphrase_fh,
				     status     => $status_fh,
				   );

  my $pid = do {
    if ($sign) {
      $gnupg->sign_and_encrypt( handles => $handles );
    } else {
      $gnupg->encrypt( handles => $handles );
    }
  };

  die "NO PASSPHRASE" unless defined $passphrase_fh;
  print $passphrase_fh $self->{passphrase};
  close $passphrase_fh;

 # this passes in the plaintext
  my $plaintext;
  if ($workingentity eq $entity) {
    $plaintext= $entity->parts(0)->as_string;
  } else {
    $plaintext=$workingentity->as_string;
  }

  # no need to mangle line endings for encryption (RFC3156)
  # $plaintext =~ s/\n/\x0D\x0A/sg;
  # should we store this back into the body?

  print $input $plaintext;

  # DEBUG:
  #print "ENCRYPTING THIS STRING ----->\n";
#  print $plaintext;
#  print "<----\n";

  close $input;

  my @ciphertext   = <$output>;   # reading the output
  my @error_output = <$error>;    # reading the error
  my @status_info  = <$status_fh>;# read the status info

  # clean up...
  close $output;
  close $error;
  close $status_fh;

  waitpid $pid, 0;
  my $exit_value  = $? >> 8;
  $self->{last_message} = [@error_output];


  $entity->parts([]); # eliminate all parts

  $entity->attach(Type => "application/pgp-encrypted",
		  Disposition => "inline",
		  Filename => "msg.asc",
		  Data => ["Version: 1",""],
		  Encoding => "7bit");
  $entity->attach(Type => "application/octet-stream",
		  Disposition => "inline",
		  Data => [@ciphertext],
		  Encoding => "7bit");

  $entity->head->mime_attr("Content-Type","multipart/encrypted");
  $entity->head->mime_attr("Content-Type.protocol","application/pgp-encrypted");

  $exit_value;
}

=head2 is_signed

  best guess as to whether a message is signed or not (by looking at
  the mime type and message content)

 Input:
   MIME::Entity containing email message to test

 Output:
  True or False value

=head2 is_encrypted

  best guess as to whether a message is signed or not (by looking at
  the mime type and message content)

 Input:
   MIME::Entity containing email message to test

 Output:
  True or False value

=cut

sub is_signed {
  my ($self,$entity) = @_;
  return 1
    if (($entity->effective_type =~ m!multipart/signed!)
	||
	($entity->as_string =~ m!^-----BEGIN PGP SIGNED MESSAGE-----!m));
  return 0;
}

sub is_encrypted {
  my ($self,$entity) = @_;
  return 1
    if (($entity->effective_type =~ m!multipart/encrypted!)
	||
	($entity->as_string =~ m!^-----BEGIN PGP MESSAGE-----!m));
  return 0;
}

# FIXME: there's no reason why is_signed and is_encrypted couldn't be
# static (class) methods, so maybe we should support that.


# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__

=head1 LICENSE

Copyright 2003 Best Practical Solutions, LLC

This program is free software; you can redistribute it and/or modify
it under the terms of either:

    a) the GNU General Public License as published by the Free
    Software Foundation; version 2
    http://www.opensource.org/licenses/gpl-license.php

    b) the "Artistic License"
    http://www.opensource.org/licenses/artistic-license.php

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See either the
GNU General Public License or the Artistic License for more details.

=head1 AUTHOR

Robert Spier

=head1 BUGS/ISSUES/PATCHES

Please send all bugs/issues/patches to
    bug-Mail-GnuPG@rt.cpan.org

=head1 SEE ALSO

L<perl>.

GnuPG::Interface,

MIME::Entity

=cut
