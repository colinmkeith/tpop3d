use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'AUTHOR'    => 'Chris Lightfoot <chris@ex-parrot.com>',
    'ABSTRACT'  => 'Library for tpop3d external authentication programs',
    'PREREQ_PM' => { 'Digest::MD5' => 0 },
    'NAME'	=> 'TPOP3D::AuthDriver',
    'VERSION_FROM' => 'AuthDriver.pm', # finds $VERSION
);
