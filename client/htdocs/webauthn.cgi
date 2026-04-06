#!/usr/bin/perl
#
# WebAuthn JSON API proxy for NicToolClient
#
# Accepts JSON POST requests, validates CSRF, forwards to
# NicToolServer via SOAP, and returns JSON responses.
#

use strict;
use warnings;

use JSON;

require 'nictoolclient.conf';

main();

sub main {
    my $q      = new CGI();
    my $nt_obj = new NicToolClient($q);

    return if $nt_obj->check_setup ne 'OK';

    # Only accept POST with JSON content
    if ( $q->request_method() ne 'POST' ) {
        send_json( 405, { error_code => 405, error_msg => 'Method not allowed' } );
        return;
    }

    my $body = $q->param('POSTDATA') || $q->param('keywords') || '';
    if ( !$body ) {

        # Try reading raw stdin for JSON
        local $/;
        $body = <STDIN> if !$body;
    }

    my $request;
    eval { $request = decode_json($body); };
    if ( $@ || !$request ) {
        send_json( 400, { error_code => 400, error_msg => 'Invalid JSON' } );
        return;
    }

    my $action = $request->{action} || '';
    my $data   = $request->{data}   || {};

    # CSRF validation
    my $csrf_token  = $request->{csrf_token}     || '';
    my $cookie_csrf = $q->cookie('NicTool_csrf') || '';
    if ( !$csrf_token || !$cookie_csrf || $csrf_token ne $cookie_csrf ) {
        send_json( 403, { error_code => 403, error_msg => 'CSRF validation failed' } );
        return;
    }

    # Pre-session actions (no session cookie required)
    my %no_session = map { $_ => 1 } qw(
        webauthn_get_auth_options
        webauthn_verify_auth
    );

    my %params = ( action => $action );

    if ( !$no_session{$action} ) {

        # Authenticated actions need session cookie
        my $cookie = $q->cookie('NicTool');
        if ( !$cookie ) {
            send_json( 403, { error_code => 403, error_msg => 'Not authenticated' } );
            return;
        }
        $params{nt_user_session} = $cookie;
    }

    # Merge request data into params
    for my $key ( keys %$data ) {
        $params{$key} = $data->{$key};
    }

    my $response = $nt_obj->{nt_server_obj}->send_request(%params);

    if ( !ref $response ) {
        send_json( 500, { error_code => 500, error_msg => $response || 'Server error' } );
        return;
    }

    # For passkey login success, set the session cookie
    if (   $action eq 'webauthn_verify_auth'
        && $response->{nt_user_session} )
    {
        my $session = $response->{nt_user_session};
        my $secure  = ( $ENV{HTTPS} || '' ) eq 'on' ? '; Secure' : '';
        print "Set-Cookie: NicTool=$session; Path=/; HttpOnly; SameSite=Strict$secure\n";
    }

    send_json( 200, $response );
}

sub send_json {
    my ( $status, $data ) = @_;
    print "Content-Type: application/json\r\n\r\n";
    print encode_json($data);
}

1;
