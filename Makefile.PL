use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'CPM',
    AUTHOR              => q{Juan José 'Peco' San Martín <peco@cpan.org>},
    VERSION_FROM        => 'lib/CPM.pm',
    ABSTRACT_FROM       => 'lib/CPM.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'CPM-*' },
);
