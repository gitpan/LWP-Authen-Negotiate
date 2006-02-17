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

our $VERSION = '0.03';


use GSSAPI;
use MIME::Base64 "2.12";
use URI;

my $MECHS = {
	KRB5 => gss_mech_krb5,
	SPNEGO => gss_mech_spnego
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
    #$target->display($tname);
    #LWP::Debug::debug("Using HTTP@".$uri->host." -> ".$tname);
    my $auth_header = $proxy ? "Proxy-Authorization" : "Authorization";

    my $itoken;
    foreach ($response->header('WWW-Authenticate')) {
      last if /^Negotiate (.+)/ && ($itoken=decode_base64($1));
    }

    my $ctx = GSSAPI::Context->new();
    my $mech = $ENV{LWP_AUTHEN_NEGOTIATE_MECH} || 'KRB5';
    my $imech = mech2oid($mech);
    $imech = gss_mech_krb5 unless defined $imech;
    my $iflags = GSS_C_MUTUAL_FLAG;
    $iflags |= GSS_C_DELEG_FLAG if $ENV{LWP_AUTHEN_NEGOTIATE_DELEGATE};
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


LWP::Authen::Negotiate - GSSAPI Authentication Plugin for LWP

=head1 SYNOPSIS

just install the module, LWP uses it as plugin.
(LWP searches at location LWP::Authen::Negotiate for
a module that can handle HTTP Negotiate if the Webserver
is able to do HTTP-Negotiate).

Use your LWP::UserAgent Scripts as usual

=head1 DESCRIPTION

To see what ist going on add

   use LWP::Debug qw(+);

to yor LWP-using Scripts.


=head2 EXPORT


None by default

=head2 ENVIROMENT

=over

=item LWP_AUTHEN_NEGOTIATE_MECH

selects the GSSAPI-mechanism to use: 'KRB5' or 'SPNEGO' (if your GSSAPI supports it). Since
SPNEGO isn't widely deployed yet 'KRB5' is the default. This may change in the future. Always
set LWP_AUTHEN_NEGOTIATE_MECH to indicate your preference.

=item LWP_AUTHEN_NEGOTIATE_DELEGATE

Define to enable ticket forwarding to webserver.

=back

=head1 SEE ALSO

GSSAPI

http://www.kerberosprotocols.org/index.php/Web

http://www.kerberosprotocols.org/index.php/Draft-brezak-spnego-http-03.txt

http://modauthkerb.sourceforge.net/

=head1 SUPPORT

=over

=item http://perlgssapi.sourceforge.net/

Project home of GSSAPI related modules

=item Mailinglists

=over

=item perlgssapi-users@lists.sourceforge.net

User questions

=item perlgssapi-developer@lists.sourceforge.net

Developer discussions

=back

=back

=head1 AUTHOR

Leif Johannson, E<lt>leifj@it.su.seE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Leif Johannson, E<lt>leifj@it.su.seE<gt>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.


=cut
