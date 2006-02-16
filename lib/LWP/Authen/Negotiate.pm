package LWP::Authen::Negotiate;

use strict;
use warnings;

require Exporter;
use AutoLoader qw(AUTOLOAD);

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use LWP::Authen::Negotiate ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '0.02';


use GSSAPI;
use MIME::Base64 "2.12";
use URI;

my $MECHS = {
	KRB5 => GSSAPI::OID::gss_mech_krb5
};

sub mech2oid
{
	$MECHS->{$_[0]};
}

sub listmechs
{
	keys %{$MECHS};
}

sub authenticate
  {
    LWP::Debug::debug("authenticate() called");
    my ($class,$ua,$proxy,$auth_param,$response,$request,$arg,$size) = @_;

    my $uri = URI->new($request->uri);
	my ($otime,$omech,$otoken,$oflags);
    my $target;
    my $status = GSSAPI::Name->import($target,"HTTP@".$uri->host,GSSAPI::OID::gss_nt_hostbased_service);
	my $tname;
	$target->display($tname);
	#warn "Using HTTP@".$uri->host." -> ".$tname."\n";
    my $auth_header = $proxy ? "Proxy-Authorization" : "Authorization";

    my $itoken;
    foreach ($response->header('WWW-Authenticate')) {
      last if /^Negotiate (.+)/ && ($itoken=decode_base64($1));
    }

    my $ctx = GSSAPI::Context->new();
    my $mech = $ENV{LWP_AUTHEN_NEGOTIATE_MECH} || 'KRB5';
    my $imech = mech2oid($mech);
    $imech = GSSAPI::OID::gss_mech_krb5 unless $imech;
    my $iflags = GSS_C_MUTUAL_FLAG;
    my $bindings = GSS_C_NO_CHANNEL_BINDINGS;
    my $creds = GSS_C_NO_CREDENTIAL;
    my $itime = 0;
    $status = $ctx->init($creds,$target,$imech,$iflags,$itime,$bindings,$itoken,$omech,$otoken,$oflags,$otime);
	
  STATUS:
    {
      $status->major == GSS_S_COMPLETE || $status->major == GSS_S_CONTINUE_NEEDED and do {
		if ($otoken || $status->major == GSS_S_CONTINUE_NEEDED)
		  {
		    my $referral = $request->clone;
		    $referral->header($auth_header => "Negotiate ".encode_base64($otoken,""));
		    return $ua->request($referral,$arg,$size,$response);
		  }
      },last STATUS;
      
      do {
      	$response->header("Client-Warning"=>"$status");
      	return $response;
      },last STATUS;
    };

  }

# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

LWP::Authen::Negotiate - Perl extension for blah blah blah

=head1 SYNOPSIS

  use LWP::Authen::Negotiate;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for LWP::Authen::Negotiate, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

A. U. Thor, E<lt>leifj@it.su.seE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2005 by A. U. Thor

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.


=cut
