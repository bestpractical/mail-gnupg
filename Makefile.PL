use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'Mail::GnuPG',
    'VERSION_FROM'	=> 'GnuPG.pm', # finds $VERSION
    'PREREQ_PM'		=> {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM => 'GnuPG.pm', # retrieve abstract from module
       AUTHOR     => 'A. U. Thor <a.u.thor@a.galaxy.far.far.away>') : ()),
);
