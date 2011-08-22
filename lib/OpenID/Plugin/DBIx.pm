package OpenID::Plugin::DBIx;
use Mojo::Base 'Mojolicious::Plugin';
use DBI qw(:utils);
use DBIx::Simple;
use SQL::Abstract;
use Carp;

my $DBIX;

my %COMMON_DBH_HANDLERS = (
  RaiseError  => 1,
  HandleError => sub { Carp::croak(shift) },
  AutoCommit  => 1,
);

my $DRIVER_DBH_HANDLERS = {
  'DBI:mysql'  => {mysql_enable_utf8 => 1, mysql_bind_type_guessing => 1},
  'DBI:SQLite' => {sqlite_unicode    => 1},
  'DBI:Pg'     => {pg_enable_utf8    => 1}
};

sub register {
  my ($self, $app, $config) = @_;

  $config ||= {};
  $app->helper('dbix', sub { dbix($config, $self, $app) });
  return;
} 

sub dbix {
  my $config = shift;
  my $c      = shift;
  my $app    = shift;
  if ($DBIX) { return $DBIX; }
  $config->{db_dsn}
    ||= $config->{db_driver}
    . ':database='
    . $config->{db_name}
    . ';host='
    . $config->{db_host};

  $DBIX = DBIx::Simple->connect(
    $config->{db_dsn}, $config->{db_user},
    $config->{db_password},
    {%COMMON_DBH_HANDLERS, %{$DRIVER_DBH_HANDLERS->{$config->{db_driver}} || {}}}
  );
  $DBIX->lc_columns = 1;
  if ($config->{debug}) {
    $DBIX->dbh->{Callbacks} = {
      prepare => sub {
        my ($dbh, $query, $attrs) = @_;

        $app && $app->log->debug("Preparing query:\n$query\n");
        return;
      },
    };
  }
  $DBIX->abstract = SQL::Abstract->new();
  return $DBIX;
}

sub instance {
  return $DBIX
    || Carp::confess(__PACKAGE__
      . ' is not instantiated. Do $app->plugin("'
      . __PACKAGE__
      . '"); to instatiate it');
}
1;

