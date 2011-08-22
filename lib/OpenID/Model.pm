package OpenID::Model;
use Mojo::Base -base;
use Carp();

sub dbix { return OpenID::Plugin::DBIx::instance() }

1;
