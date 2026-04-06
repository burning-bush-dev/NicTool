use strict;
use warnings;

use lib 't';
use NicToolTest;
use Test::More;
use JSON;
use MIME::Base64 qw(decode_base64url);

BEGIN {
    use_ok('NicToolServer');
    use_ok('NicToolServer::WebAuthn');
}

# -- DB setup (same pattern as 01_data.t) --

$NicToolServer::dsn     = Config('dsn');
$NicToolServer::db_user = Config('db_user');
$NicToolServer::db_pass = Config('db_pass');

my $dbh = NicToolServer->dbh();
ok( $dbh, 'dbh handle' ) or BAIL_OUT('no database connection');

my $wa = NicToolServer::WebAuthn->new( undef, undef, $dbh );
ok( $wa, 'WebAuthn instance' );

my $test_uid    = 1;              # root user, always exists
my $test_prefix = "test_wa_$$";

# Save and clear WebAuthn options for clean test state
my $orig_rp_id  = $wa->get_option('webauthn_rp_id');
my $orig_origin = $wa->get_option('webauthn_origin');

$wa->exec_query( 'DELETE FROM nt_options WHERE option_name = ?', 'webauthn_rp_id' );
$wa->exec_query( 'DELETE FROM nt_options WHERE option_name = ?', 'webauthn_origin' );

# =====================================================================
# T1: Unconfigured returns error 600
# =====================================================================
subtest 'T1: unconfigured error' => sub {
    my $r1 = $wa->generate_registration_options( { nt_user_id => $test_uid } );
    is( $r1->{error_code}, 600, 'registration: unconfigured returns 600' );

    my $r2 = $wa->generate_authentication_options( { username => 'root' } );
    is( $r2->{error_code}, 600, 'auth with username: unconfigured returns 600' );

    my $r3 = $wa->generate_authentication_options( {} );
    is( $r3->{error_code}, 600, 'auth usernameless: unconfigured returns 600' );
};

# Insert test options for remaining tests
my $test_rp_id  = 'localhost';
my $test_origin = 'https://localhost:8443';

$wa->exec_query( 'INSERT INTO nt_options (option_name, option_value) VALUES (?, ?)',
    [ 'webauthn_rp_id', $test_rp_id ] );
$wa->exec_query( 'INSERT INTO nt_options (option_name, option_value) VALUES (?, ?)',
    [ 'webauthn_origin', $test_origin ] );

# =====================================================================
# T2: Challenge generation
# =====================================================================
subtest 'T2: challenge generation' => sub {
    my $c = $wa->_generate_challenge();
    ok( defined $c,       'challenge is defined' );
    ok( length($c) >= 40, 'challenge >= 40 chars (32 bytes base64url)' );
    unlike( $c, qr/[+\/=]/, 'valid base64url (no +/= chars)' );

    my $decoded = decode_base64url($c);
    is( length($decoded), 32, 'decoded challenge is 32 bytes' );

    my %seen;
    my $all_unique = 1;
    for ( 1 .. 100 ) {
        my $ch = $wa->_generate_challenge();
        if ( $seen{$ch}++ ) { $all_unique = 0; last; }
    }
    ok( $all_unique, '100 challenges are all unique' );
};

# =====================================================================
# T3: Challenge lifecycle
# =====================================================================
subtest 'T3: challenge lifecycle' => sub {
    my $now = time();

    # Valid challenge — consume succeeds
    my $ch1 = "${test_prefix}_life1";
    $wa->exec_query(
        'INSERT INTO nt_user_webauthn_challenge
            (nt_user_id, challenge, ceremony_type,
             created_at, expires_at) VALUES (??)',
        [ $test_uid, $ch1, 'authentication', $now, $now + 300 ]
    );
    my $row = $wa->_consume_challenge( $ch1, 'authentication', $test_uid );
    ok( $row, 'valid challenge consumed' );
    is( $row->{challenge}, $ch1, 'returned row matches' );

    # Replay rejected
    ok( !$wa->_consume_challenge( $ch1, 'authentication', $test_uid ), 'replay rejected' );

    # Expired challenge
    my $ch2 = "${test_prefix}_expired";
    $wa->exec_query(
        'INSERT INTO nt_user_webauthn_challenge
            (nt_user_id, challenge, ceremony_type,
             created_at, expires_at) VALUES (??)',
        [ $test_uid, $ch2, 'authentication', $now - 600, $now - 300 ]
    );
    ok( !$wa->_consume_challenge( $ch2, 'authentication', $test_uid ),
        'expired challenge rejected' );

    # Wrong ceremony type
    my $ch3 = "${test_prefix}_wrongtype";
    $wa->exec_query(
        'INSERT INTO nt_user_webauthn_challenge
            (nt_user_id, challenge, ceremony_type,
             created_at, expires_at) VALUES (??)',
        [ $test_uid, $ch3, 'registration', $now, $now + 300 ]
    );
    ok( !$wa->_consume_challenge( $ch3, 'authentication', $test_uid ),
        'wrong ceremony type rejected' );

    # Wrong user ID
    my $ch4 = "${test_prefix}_wronguid";
    $wa->exec_query(
        'INSERT INTO nt_user_webauthn_challenge
            (nt_user_id, challenge, ceremony_type,
             created_at, expires_at) VALUES (??)',
        [ $test_uid, $ch4, 'authentication', $now, $now + 300 ]
    );
    ok( !$wa->_consume_challenge( $ch4, 'authentication', 99999 ), 'wrong user ID rejected' );

    # NULL user ID (usernameless flow)
    my $ch5 = "${test_prefix}_nulluid";
    $wa->exec_query(
        'INSERT INTO nt_user_webauthn_challenge
            (nt_user_id, challenge, ceremony_type,
             created_at, expires_at) VALUES (??)',
        [ undef, $ch5, 'authentication', $now, $now + 300 ]
    );
    my $null_row = $wa->_consume_challenge( $ch5, 'authentication', undef );
    ok( $null_row, 'NULL uid challenge consumed (usernameless)' );
    is( $null_row->{challenge}, $ch5, 'NULL uid row matches' );

    # Cleanup removes expired
    $wa->_cleanup_expired_challenges();
    my $remaining = $wa->exec_query(
        'SELECT COUNT(*) AS cnt
           FROM nt_user_webauthn_challenge
          WHERE challenge = ?', $ch2
    );
    is( $remaining->[0]{cnt}, 0, 'cleanup removed expired row' );
};

# =====================================================================
# T4: generate_registration_options
# =====================================================================
subtest 'T4: registration options' => sub {

    # Missing nt_user_id
    is( $wa->generate_registration_options( {} )->{error_code}, 301, 'missing uid returns 301' );

    # Nonexistent user
    is( $wa->generate_registration_options( { nt_user_id => 99999 } )->{error_code},
        404, 'nonexistent user returns 404' );

    # Valid call
    my $r = $wa->generate_registration_options( { nt_user_id => $test_uid } );
    is( $r->{error_code}, 200, 'valid call returns 200' );
    ok( $r->{options}, 'options field present' );

    my $opts = decode_json( $r->{options} );
    ok( $opts->{challenge}, 'has challenge' );
    is( $opts->{rp}{id}, $test_rp_id, 'correct rp.id' );
    ok( $opts->{user}{id},                        'has user.id' );
    ok( ref $opts->{pubKeyCredParams} eq 'ARRAY', 'pubKeyCredParams is array' );

    # user.id decodes to packed uid
    my $decoded_uid =
        unpack( 'N', decode_base64url( $opts->{user}{id} ) );
    is( $decoded_uid, $test_uid, 'user.id encodes uid' );
};

# =====================================================================
# T5: generate_authentication_options WITH username
# =====================================================================
subtest 'T5: auth options with username' => sub {

    # Nonexistent user
    is( $wa->generate_authentication_options( { username => 'nonexistent_xyzzy_999' } )
            ->{error_code},
        403,
        'nonexistent user returns 403'
    );

    # User with no credentials
    is( $wa->generate_authentication_options( { username => 'root' } )->{error_code},
        403, 'no credentials returns 403' );

    # Insert a test credential
    my $cred_id = "${test_prefix}_auth_cred";
    $wa->exec_query(
        'INSERT INTO nt_user_webauthn_credential
            (nt_user_id, credential_id, credential_pubkey,
             signature_count, friendly_name, transports,
             created_at) VALUES (??)',
        [ $test_uid, $cred_id, 'fake_pubkey_b64', 0, 'Test Auth Key', 'internal,hybrid', time() ]
    );

    my $r = $wa->generate_authentication_options( { username => 'root' } );
    is( $r->{error_code}, 200, 'with credential returns 200' );

    my $opts = decode_json( $r->{options} );
    is( ref $opts->{allowCredentials}, 'ARRAY', 'allowCredentials is array' );
    ok( scalar @{ $opts->{allowCredentials} } >= 1, 'at least one credential' );

    my ($match) = grep { $_->{id} eq $cred_id } @{ $opts->{allowCredentials} };
    ok( $match, 'test credential in allowCredentials' );
    is( ref $match->{transports}, 'ARRAY', 'transports parsed to array' );
};

# =====================================================================
# T6: generate_authentication_options WITHOUT username (usernameless)
# =====================================================================
subtest 'T6: auth options usernameless' => sub {
    my $r = $wa->generate_authentication_options( {} );
    is( $r->{error_code}, 200, 'no username returns 200' );

    my $opts = decode_json( $r->{options} );
    is( ref $opts->{allowCredentials},         'ARRAY', 'allowCredentials is array' );
    is( scalar @{ $opts->{allowCredentials} }, 0,       'allowCredentials is empty' );
    ok( $opts->{challenge}, 'challenge present' );

    # Stored with NULL uid
    my $rows = $wa->exec_query(
        'SELECT * FROM nt_user_webauthn_challenge
          WHERE challenge = ? AND nt_user_id IS NULL',
        $opts->{challenge}
    );
    ok( $rows && $rows->[0], 'challenge stored with NULL nt_user_id' );

    # Consumable with undef
    ok( $wa->_consume_challenge( $opts->{challenge}, 'authentication', undef ),
        'NULL uid challenge consumable' );
};

# =====================================================================
# T7: Credential CRUD
# =====================================================================
subtest 'T7: credential CRUD' => sub {

    # Clean slate
    $wa->exec_query(
        'DELETE FROM nt_user_webauthn_credential
          WHERE credential_id LIKE ?', "${test_prefix}_crud%"
    );

    # Missing uid
    is( $wa->get_user_credentials( {} )->{error_code}, 301, 'get: missing uid returns 301' );
    is( $wa->revoke_credential( { nt_user_id => 1 } )->{error_code},
        301, 'revoke: missing cred_id returns 301' );
    is( $wa->rename_credential( { nt_user_id => 1 } )->{error_code},
        301, 'rename: missing cred_id returns 301' );
    is(
        $wa->rename_credential(
            {   nt_user_id                => 1,
                nt_webauthn_credential_id => 1
            }
        )->{error_code},
        301,
        'rename: missing name returns 301'
    );

    # Insert credential
    my $cred_id = "${test_prefix}_crud1";
    $wa->exec_query(
        'INSERT INTO nt_user_webauthn_credential
            (nt_user_id, credential_id, credential_pubkey,
             signature_count, friendly_name, created_at)
            VALUES (??)',
        [ $test_uid, $cred_id, 'fake_pk', 0, 'My Key', time() ]
    );

    # List includes it
    my $list = $wa->get_user_credentials( { nt_user_id => $test_uid } );
    is( $list->{error_code}, 200, 'list returns 200' );
    my ($found) = grep { $_->{credential_id} eq $cred_id } @{ $list->{credentials} };
    ok( $found, 'credential in list' );
    is( $found->{friendly_name}, 'My Key', 'name correct' );
    my $db_id = $found->{nt_webauthn_credential_id};

    # Rename
    is(
        $wa->rename_credential(
            {   nt_user_id                => $test_uid,
                nt_webauthn_credential_id => $db_id,
                friendly_name             => 'Renamed',
            }
        )->{error_code},
        200,
        'rename returns 200'
    );
    my $list2 = $wa->get_user_credentials( { nt_user_id => $test_uid } );
    my ($renamed) = grep { $_->{credential_id} eq $cred_id } @{ $list2->{credentials} };
    is( $renamed->{friendly_name}, 'Renamed', 'rename took effect' );

    # Revoke
    is(
        $wa->revoke_credential(
            {   nt_user_id                => $test_uid,
                nt_webauthn_credential_id => $db_id,
            }
        )->{error_code},
        200,
        'revoke returns 200'
    );
    my $list3 = $wa->get_user_credentials( { nt_user_id => $test_uid } );
    my ($gone) = grep { $_->{credential_id} eq $cred_id } @{ $list3->{credentials} };
    ok( !$gone, 'revoked credential gone from list' );
};

# =====================================================================
# T8: verify_registration error paths
# =====================================================================
subtest 'T8: verify_registration errors' => sub {
    is( $wa->verify_registration( {} )->{error_code}, 301, 'missing uid returns 301' );
    is( $wa->verify_registration( { nt_user_id => $test_uid } )->{error_code},
        301, 'missing attestation fields returns 301' );
    is(
        $wa->verify_registration(
            {   nt_user_id             => $test_uid,
                challenge_b64          => 'nonexistent',
                client_data_json_b64   => 'fake',
                attestation_object_b64 => 'fake',
            }
        )->{error_code},
        403,
        'invalid challenge returns 403'
    );
};

# =====================================================================
# T9: verify_authentication error paths
# =====================================================================
subtest 'T9: verify_authentication errors' => sub {
    is( $wa->verify_authentication( {} )->{error_code}, 301, 'missing fields returns 301' );
    is(
        $wa->verify_authentication(
            {   challenge_b64          => 'fake',
                credential_id_b64      => 'nonexistent_cred',
                client_data_json_b64   => 'fake',
                authenticator_data_b64 => 'fake',
                signature_b64          => 'fake',
            }
        )->{error_code},
        403,
        'unknown credential returns 403'
    );

    # Revoked credential
    my $rev_cred = "${test_prefix}_rev_auth";
    $wa->exec_query(
        'INSERT INTO nt_user_webauthn_credential
            (nt_user_id, credential_id, credential_pubkey,
             signature_count, revoked, created_at)
            VALUES (??)',
        [ $test_uid, $rev_cred, 'fake', 0, 1, time() ]
    );
    is(
        $wa->verify_authentication(
            {   challenge_b64          => 'fake',
                credential_id_b64      => $rev_cred,
                client_data_json_b64   => 'fake',
                authenticator_data_b64 => 'fake',
                signature_b64          => 'fake',
            }
        )->{error_code},
        403,
        'revoked credential returns 403'
    );
};

# =====================================================================
# Cleanup
# =====================================================================
END {
    if ($wa) {
        $wa->exec_query(
            'DELETE FROM nt_user_webauthn_challenge
              WHERE challenge LIKE ?', "${test_prefix}%"
        );
        $wa->exec_query(
            'DELETE FROM nt_user_webauthn_credential
              WHERE credential_id LIKE ?', "${test_prefix}%"
        );

        # Clean generated challenges from registration/auth options
        $wa->exec_query(
            'DELETE FROM nt_user_webauthn_challenge
              WHERE nt_user_id = ? AND consumed = 0', $test_uid
        );
        $wa->exec_query(
            'DELETE FROM nt_user_webauthn_challenge
              WHERE nt_user_id IS NULL AND consumed = 0'
        );

        # Restore original options
        $wa->exec_query( 'DELETE FROM nt_options WHERE option_name = ?', 'webauthn_rp_id' );
        $wa->exec_query( 'DELETE FROM nt_options WHERE option_name = ?', 'webauthn_origin' );
        if ($orig_rp_id) {
            $wa->exec_query(
                'INSERT INTO nt_options
                    (option_name, option_value) VALUES (?, ?)',
                [ 'webauthn_rp_id', $orig_rp_id ]
            );
        }
        if ($orig_origin) {
            $wa->exec_query(
                'INSERT INTO nt_options
                    (option_name, option_value) VALUES (?, ?)',
                [ 'webauthn_origin', $orig_origin ]
            );
        }
    }
}

done_testing();
