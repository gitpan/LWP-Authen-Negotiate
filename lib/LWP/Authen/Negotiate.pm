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


use MIME::Base64 "2.12";
use GSSAPI 0.18;


sub authenticate
  {
    LWP::Debug::debug("authenticate() called");
    my ($class,$ua,$proxy,$auth_param,$response,$request,$arg,$size) = @_;

    my $uri = URI->new($request->uri);
    my $targethost = $request->uri()->host();

    my ($otime,$omech,$otoken,$oflags);
    my $target;
    my $status;
    TRY: {
        $status  = GSSAPI::Name->import(
                      $target,
                      join( '@', 'HTTP', $targethost ),
		      GSSAPI::OID::gss_nt_hostbased_service
		 );
        last TRY if  ( $status->major != GSS_S_COMPLETE );
        my $tname;
        $target->display( $tname );
        LWP::Debug::debug("target hostname $targethost");
        LWP::Debug::debug("GSSAPI servicename $tname");
        my $auth_header = $proxy ? "Proxy-Authorization" : "Authorization";

        my $itoken = q{};
        foreach ($response->header('WWW-Authenticate')) {
          last if /^Negotiate (.+)/ && ($itoken=decode_base64($1));
        }

        my $ctx = GSSAPI::Context->new();
        my $imech = GSSAPI::OID::gss_mech_krb5;
        #my $iflags = GSS_C_MUTUAL_FLAG;
        my $iflags = GSS_C_REPLAY_FLAG;
        my $bindings = GSS_C_NO_CHANNEL_BINDINGS;
        my $creds = GSS_C_NO_CREDENTIAL;
        my $itime = 0;
	$status = $ctx->init($creds,$target,$imech,$iflags,$itime,$bindings,$itoken,
	                     $omech,$otoken,$oflags,$otime);
        if  (    $status->major == GSS_S_COMPLETE
	      or $status->major == GSS_S_CONTINUE_NEEDED   ) {
            LWP::Debug::debug( 'successfull $ctx->init()');
	    my $referral = $request->clone;
	    $referral->header( $auth_header => "Negotiate ".encode_base64($otoken,""));
	    return $ua->request( $referral, $arg, $size, $response );
	}
    }
    if ( $status->major != GSS_S_COMPLETE  ) {
       LWP::Debug::debug( $status->generic_message());
       LWP::Debug::debug( $status->specific_message() );
       return $response;
    }
}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

LWP::Authen::Negotiate - GSSAPI Authentication Plugin for LWP

=head1 SYNOPSIS

just install, LWP uses it as authentication plugin.
Use your LWP::UserAgent Scripts as usual based on your GSSAPI
installation (MIT Kerberos or Heimdal)

=head1 DESCRIPTION

To see what ist going on add

   use LWP::Debug qw(+);

to yor LWP using Scripts.

(e.g. too see what is going wrong with GSSAPI...)

=head1 DEBUGGING

To see what ist going on (and going wrong) add

   use LWP::Debug qw(+);

to yor LWP using Scripts.

(e.g. too see what is going wrong with GSSAPI...)

the output will look like this:

   LWP::UserAgent::new: ()
   LWP::UserAgent::request: ()
   LWP::UserAgent::send_request: GET http://testwurst.grolmsnet.lan:8090/geheim/
   LWP::UserAgent::_need_proxy: Not proxied
   LWP::Protocol::http::request: ()
   LWP::Protocol::collect: read 478 bytes
   LWP::UserAgent::request: Simple response: Unauthorized
   LWP::Authen::Negotiate::authenticate: authenticate() called
   LWP::Authen::Negotiate::authenticate: target hostname testwurst.grolmsnet.lan
   LWP::Authen::Negotiate::authenticate: GSSAPI servicename     HTTP/moerbsen.grolmsnet.lan@GROLMSNET.LAN
   LWP::Authen::Negotiate::authenticate:  Miscellaneous failure (see text)
   LWP::Authen::Negotiate::authenticate: open(/tmp/krb5cc_1000): file not found

In this case the credentials cache was empty.
Run kinit first ;-)

=head1 SEE ALSO

=over

=item http://www.kerberosprotocols.org/index.php/Draft-brezak-spnego-http-03.txt

Description of WWW-Negotiate protol

=item http://modauthkerb.sourceforge.net/

the Kerberos and SPNEGO Authentication module for Apache mod_auth_kerb


=item http://perlgssapi.sourceforge.net/

Module Homepage

=item http://www.kerberosprotocols.org/index.php/Web

Sofware and APIs related to WWW-Negotiate

=item http://www.grolmsnet.de/kerbtut/

describes how to let mod_auth_kerb play together
with Internet Explorer and Windows2003 Server

=back




=head1 AUTHOR

Achim Grolms, E<lt>achim@grolmsnet.deE<gt>

http://perlgssapi.sourceforge.net/

Thanks to Leif Johansson, Harald Joerg, Christopher Odenbach


=head1 BUGS

Ticket forwarding is not supportes at the moment.


=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Achim Grolms <perl@grolmsnet.de>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.4 or,
at your option, any later version of Perl 5 you may have available.


=cut
