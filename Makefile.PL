use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'Mail::GnuPG',
    'VERSION_FROM'	=> 'GnuPG.pm', # finds $VERSION
    'PREREQ_PM'		=> {
			    'GnuPG::Interface' => 0,
			    'IO::Handle'       => 0,
			    'MIME::Entity'     => 0,
			    'File::Temp'       => 0,
			    'File::Spec'       => 0,
			    'MIME::Parser'     => 0,
			    'Mail::Address'    => 0,
			    'Test::More',      => 0,
			    'Test::Pod',       => 0
			   },
    ABSTRACT_FROM       => 'GnuPG.pm', # retrieve abstract from module
    AUTHOR              => 'Robert Spier <rspier@cpan.org>',
);
