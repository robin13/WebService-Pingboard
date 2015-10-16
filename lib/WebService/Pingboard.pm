package WebService::Pingboard;
# ABSTRACT: Interface to Pingboard API
use Moose;
use MooseX::Params::Validate;
use MooseX::WithCache;
use LWP::UserAgent;
use HTTP::Request;
use HTTP::Headers;
use JSON::MaybeXS;
use YAML;
use Encode;
use URI::Encode qw/uri_encode/;

our $VERSION = 0.005;

=head1 NAME

WebService::Pingboard

=head1 DESCRIPTION

Interaction with Pingboard

This module uses MooseX::Log::Log4perl for logging - be sure to initialize!

=cut


=head1 ATTRIBUTES

=over 4

=item cache

Optional.

Provided by MooseX::WithX - optionally pass a Cache::FileCache object to cache and avoid unnecessary requests

=cut

with "MooseX::Log::Log4perl";

# Unfortunately it is necessary to define the cache type to be expected here with 'backend'
# TODO a way to be more generic with cache backend would be better
with 'MooseX::WithCache' => {
    backend => 'Cache::FileCache',
};

=item refresh_token


=cut
has 'refresh_token' => (
    is          => 'ro',
    isa         => 'Str',
    required    => 0,
    writer      => '_set_refresh_token',
    );

=item password


=cut
has 'password' => (
    is          => 'ro',
    isa         => 'Str',
    required    => 0,
    writer      => '_set_password',
    );

=item username


=cut
has 'username' => (
    is          => 'ro',
    isa         => 'Str',
    required    => 0,
    writer      => '_set_username',
    );

=item timeout

Timeout when communicating with Pingboard in seconds.  Optional.  Default: 10 
Will only be in effect if you allow the useragent to be built in this module.

=cut
has 'timeout' => (
    is          => 'ro',
    isa         => 'Int',
    required    => 1,
    default     => 10,
    );

=item default_backoff

Optional.  Default: 10
Time in seconds to back off before retrying request.
If a 429 response is given and the Retry-Time header is provided by the api this will be overridden.

=cut
has 'default_backoff' => (
    is          => 'ro',
    isa         => 'Int',
    required    => 1,
    default     => 10,
    );

=item default_page_size

Optional. Default: 100

=cut
has 'default_page_size' => (
    is          => 'rw',
    isa         => 'Int',
    required    => 1,
    default     => 100,
    );

=item retry_on_status

Optional. Default: [ 429, 500, 502, 503, 504 ]
Which http response codes should we retry on?

=cut
has 'retry_on_status' => (
    is          => 'ro',
    isa         => 'ArrayRef',
    required    => 1,
    default     => sub{ [ 429, 500, 502, 503, 504 ] },
    );

=item max_tries

Optional.  Default: undef

Limit maximum number of times a query should be attempted before failing.  If undefined then unlimited retries

=cut
has 'max_tries' => (
    is          => 'ro',
    isa         => 'Int',
    );

=item api_url

Default: https://app.pingboard.com/api/v2/

=cut
has 'api_url' => (
    is		=> 'ro',
    isa		=> 'Str',
    required	=> 1,
    default     => 'https://app.pingboard.com/api/v2',
    );

=item user_agent

Optional.  A new LWP::UserAgent will be created for you if you don't already have one you'd like to reuse.

=cut

has 'user_agent' => (
    is		=> 'ro',
    isa		=> 'LWP::UserAgent',
    required	=> 1,
    lazy	=> 1,
    builder	=> '_build_user_agent',

    );

=item loglevel

Optionally override the global loglevel for this module

=cut

has 'loglevel' => (
    is		=> 'rw',
    isa		=> 'Str',
    trigger     => \&_set_loglevel,
    );

has '_access_token' => (
    is          => 'ro',
    isa         => 'Str',
    required    => 0,
    writer      => '_set_access_token',
    );

has '_headers' => (
    is          => 'ro',
    isa         => 'HTTP::Headers',
    writer      => '_set_headers',
    );

has '_access_token_expires' => (
    is          => 'ro',
    isa         => 'Int',
    required    => 0,
    writer      => '_set_access_token_expires',
    );

sub _set_loglevel {
    my( $self, $level ) = @_;
    $self->log->warn( "Setting new loglevel: $level" );
    $self->log->level( $level );
}

sub _build_user_agent {
    my $self = shift;
    $self->log->debug( "Building useragent" );
    my $ua = LWP::UserAgent->new(
	keep_alive	=> 1,
        timeout         => $self->timeout,
    );
    return $ua;
}

=back

=head1 METHODS

=over 4

=item valid_access_token

Will return a valid access token.

=cut

sub valid_access_token {
    my ( $self, %params ) = validated_hash(
        \@_,
        username        => { isa    => 'Str', optional => 1 },
        password        => { isa    => 'Str', optional => 1 },
        refresh_token   => { isa    => 'Str', optional => 1 },
	);

    # If we still have a valid access token, use this
    #if( $self->_access_token and $self->_access_token_expires > ( time() + 5 ) ){
    if( $self->access_token_is_valid ){
        return $self->_access_token;
    }

    $params{username}       ||= $self->username;
    $params{password}       ||= $self->password;
    $params{refresh_token}  ||= $self->refresh_token;

    my $h = HTTP::Headers->new();
    $h->header( 'Content-Type'	=> "application/json" );
    $h->header( 'Accept'	=> "application/json" );

    my $data;
    if( $params{username} and $params{refresh_token} ){
        $self->log->debug( "Requesting fresh access_token with refresh_token: $params{refresh_token}" );
        $data = $self->_request_from_api(
            method      => 'POST',
            headers     => $h,
            uri         => 'https://app.pingboard.com/oauth/token',
            options     => sprintf( 'username=%s&refresh_token=%s&grant_type=refresh_token', $params{username}, $params{refresh_token} ),
            );
    }elsif( $params{username} and $params{password} ){
        $self->log->debug( "Requesting fresh access_token with username and password for: $params{username}" );
        $data = $self->_request_from_api(
            method      => 'POST',
            headers     => $h,
            uri         => 'https://app.pingboard.com/oauth/token',
            options     => sprintf( 'username=%s&password=%s&grant_type=password', $params{username}, uri_encode( $params{password} ) ),
            );
    }else{
        die( "Cannot create valid access_token without a refresh_token or username and password" );
    }
    $self->log->debug( "Response from getting access_token:\n" . Dump( $data ) );
    my $expire_time = time() + $data->{expires_in};
    $self->log->debug( "Got new access_token: $data->{access_token} which expires at " . localtime( $expire_time ) );
    if( $data->{refresh_token} ){
        $self->log->debug( "Got new refresh_token: $data->{refresh_token}" );
        $self->_set_refresh_token( $data->{refresh_token} );
    }
    $self->_set_access_token( $data->{access_token} );
    $self->_set_access_token_expires( $expire_time );
    return $data->{access_token};
}

=item access_token_is_valid

Returns true if a valid access token exists (with at least 5 seconds validity remaining).

=cut

sub access_token_is_valid {
    my $self = shift;
    return 1 if( $self->_access_token and $self->_access_token_expires > ( time() + 5 ) );
    return 0;
}

=item headers

Returns a HTTP::Headers object with the Authorization header set with a valid access token

=cut
sub headers {
    my $self = shift;
    if( not $self->access_token_is_valid or not $self->_headers ){
        my $h = HTTP::Headers->new();
        $h->header( 'Content-Type'	=> "application/json" );
        $h->header( 'Accept'	=> "application/json" );
        $h->header( 'Authorization' => "Bearer " . $self->valid_access_token );
        $self->_set_headers( $h );
    }
    return $self->_headers;
}

=item get_users

=over 4

=item id

Optional. The user id to get

=item limit

Optional. Maximum number of entries to fetch.

=item page_size

Optional.  Page size to use when fetching.

=back

=cut

sub get_users {
    my ( $self, %params ) = validated_hash(
        \@_,
        id	    => { isa    => 'Int', optional => 1 },
        limit       => { isa    => 'Int', optional => 1 },
        page_size   => { isa    => 'Int', optional => 1 },
        options     => { isa    => 'Str', optional => 1 },
	);
    $params{field}  = 'users';
    $params{path}   = '/users' . ( $params{id} ? '/' . $params{id} : '' );
    delete( $params{id} );
    return $self->_paged_request_from_api( %params );
}

=item get_groups

=over 4

=item id (optional)

The group id to get

=item limit

Optional. Maximum number of entries to fetch.

=item page_size

Optional.  Page size to use when fetching.

=back

=cut

sub get_groups {
    my ( $self, %params ) = validated_hash(
        \@_,
        id	    => { isa    => 'Int', optional => 1 },
        limit       => { isa    => 'Int', optional => 1 },
        page_size   => { isa    => 'Int', optional => 1 },
        options     => { isa    => 'Str', optional => 1 },
	);
    $params{field}  = 'groups';
    $params{path}   = '/groups' . ( $params{id} ? '/' . $params{id} : '' );
    delete( $params{id} );
    return $self->_paged_request_from_api( %params );
}

=item get_custom_fields

=over 4

=item id (optional)

The resource id to get

=item limit

Optional. Maximum number of entries to fetch.

=item page_size

Optional.  Page size to use when fetching.

=back

=cut

sub get_custom_fields {
    my ( $self, %params ) = validated_hash(
        \@_,
        id	    => { isa    => 'Int', optional => 1 },
        limit       => { isa    => 'Int', optional => 1 },
        page_size   => { isa    => 'Int', optional => 1 },
        options     => { isa    => 'Str', optional => 1 },
	);
    $params{field}  = 'custom_fields';
    $params{path}   = '/custom_fields' . ( $params{id} ? '/' . $params{id} : '' );
    delete( $params{id} );
    return $self->_paged_request_from_api( %params );
}

=item get_linked_accounts

=over 4

=item id

The resource id to get

=back

=cut

sub get_linked_accounts {
    my ( $self, %params ) = validated_hash(
        \@_,
        id	=> { isa    => 'Int'},
        options => { isa    => 'Str', optional => 1 },
	);
    $params{field}  = 'linked_accounts';
    $params{path}   = '/linked_accounts/' . $params{id};
    delete( $params{id} );
    return $self->_paged_request_from_api( %params );
}

=item get_linked_account_providers

=over 4

=item id (optional)

The resource id to get

=item limit

Optional. Maximum number of entries to fetch.

=item page_size

Optional.  Page size to use when fetching.

=back

=cut

sub get_linked_account_providers {
    my ( $self, %params ) = validated_hash(
        \@_,
        id	    => { isa    => 'Int', optional => 1 },
        limit       => { isa    => 'Int', optional => 1 },
        page_size   => { isa    => 'Int', optional => 1 },
        options     => { isa    => 'Str', optional => 1 },
	);
    $params{field}  = 'linked_account_providers';
    $params{path}   = '/linked_account_providers' . ( $params{id} ? '/' . $params{id} : '' );
    delete( $params{id} );
    return $self->_paged_request_from_api( %params );
}

=item get_statuses

=over 4

=item id (optional)

The resource id to get

=item limit

Optional. Maximum number of entries to fetch.

=item page_size

Optional.  Page size to use when fetching.

=back

=cut

sub get_statuses {
    my ( $self, %params ) = validated_hash(
        \@_,
        id	    => { isa    => 'Int', optional => 1 },
        limit       => { isa    => 'Int', optional => 1 },
        page_size   => { isa    => 'Int', optional => 1 },
        options     => { isa    => 'Str', optional => 1 },
	);
    $params{field}  = 'statuses';
    $params{path}   = '/statuses' . ( $params{id} ? '/' . $params{id} : '' );
    delete( $params{id} );
    return $self->_paged_request_from_api( %params );
}


=item clear_cache_object_id

Clears an object from the cache.

=over 4

=item object_id

Required.  Object id to clear from the cache.

=back

Returns whether cache_del was successful or not

=cut
sub clear_cache_object_id {
    my ( $self, %params ) = validated_hash(
        \@_,
        object_id	=> { isa    => 'Str' }
	);

    $self->log->debug( "Clearing cache id: $params{object_id}" );
    my $foo = $self->cache_del( $params{object_id} );

    return $foo;
}

sub _paged_request_from_api {
    my ( $self, %params ) = validated_hash(
        \@_,
        method	    => { isa => 'Str', optional => 1, default => 'GET' },
	path	    => { isa => 'Str' },
        field       => { isa => 'Str' },
        limit       => { isa => 'Int', optional => 1 },
        page_size   => { isa => 'Int', optional => 1 },
        options     => { isa => 'Str', optional => 1 },
        body        => { isa => 'Str', optional => 1 },
    );
    my @results;
    my $page = 1;

    $params{page_size} ||= $self->default_page_size;
    if( $params{limit} and $params{limit} < $params{page_size} ){
        $params{page_size} = $params{limit};
    }

    my $response = undef;
    do{
        my %request_params = ( 
            method      => $params{method},
            path        => $params{path} . ( $params{path} =~ m/\?/ ? '&' : '?' ) . 'page=' . $page . '&page_size=' . $params{page_size},
            );
        $request_params{options} = $params{options} if( $params{options} );
        $response = $self->_request_from_api( %request_params );
	push( @results, @{ $response->{$params{field} } } );
	$page++;
      }while( $response->{meta}{$params{field}}{page} < $response->{meta}{$params{field}}{page_count} and ( not $params{limit} or scalar( @results ) < $params{limit} ) );
    return @results;
}


sub _request_from_api {
    my ( $self, %params ) = validated_hash(
        \@_,
        method	=> { isa => 'Str' },
	path	=> { isa => 'Str', optional => 1 },
        uri     => { isa => 'Str', optional => 1 },
        body    => { isa => 'Str', optional => 1 },
        headers => { isa => 'HTTP::Headers', optional => 1 },
        options => { isa => 'Str', optional => 1 },
        fields  => { isa => 'HashRef', optional => 1 },
    );
    my $url = $params{uri} || $self->api_url;
    $url .=  $params{path} if( $params{path} );
    $url .= ( $url =~ m/\?/ ? '&' : '?' )  . $params{options} if( $params{options} );

    my $request = HTTP::Request->new(
        $params{method},
        $url,
        $params{headers} || $self->headers,
        );
    $request->content( $params{body} ) if( $params{body} );

    $self->log->debug( "Requesting: " . $request->uri );
    $self->log->trace( "Request:\n" . Dump( $request ) ) if $self->log->is_trace;

    my $response;
    my $retry = 1;
    my $try_count = 0;
    do{
        my $retry_delay = $self->default_backoff;
        $try_count++;
        # Fields are a special use-case for GET requests:
        # https://metacpan.org/pod/LWP::UserAgent#ua-get-url-field_name-value
        if( $params{fields} ){
            if( $request->method ne 'GET' ){
                $self->log->logdie( 'Cannot use fields unless the request method is GET' );
            }
            my %fields = %{ $params{fields} };
            my $headers = $request->headers();
            foreach( keys( %{ $headers } ) ){
                $fields{$_} = $headers->{$_};
            }
            $self->log->trace( "Fields:\n" . Dump( \%fields ) );
            $response = $self->user_agent->get(
                $request->uri(),
                %fields,
            );
        }else{
            $response = $self->user_agent->request( $request );
        }
        if( $response->is_success ){
            $retry = 0;
        }else{
            if( grep{ $_ == $response->code } @{ $self->retry_on_status } ){
                if( $response->code == 429 ){
                    # if retry-after header exists and has valid data use this for backoff time
                    if( $response->header( 'Retry-After' ) and $response->header('Retry-After') =~ /^\d+$/ ) {
                        $retry_delay = $response->header('Retry-After');
                    }
                    $self->log->warn( sprintf( "Received a %u (Too Many Requests) response with 'Retry-After' header... going to backoff and retry in %u seconds!",
                            $response->code,
                            $retry_delay,
                            ) );
                }else{
                    $self->log->warn( sprintf( "Received a %u: %s ... going to backoff and retry in %u seconds!",
                            $response->code,
                            $response->decoded_content,
                            $retry_delay
                            ) );
                }
            }else{
                $retry = 0;
            }

            if( $retry == 1 ){
                if( not $self->max_tries or $self->max_tries > $try_count ){
                    $self->log->debug( sprintf( "Try %u failed... sleeping %u before next attempt", $try_count, $retry_delay ) );
                    sleep( $retry_delay );
                }else{
                    $self->log->debug( sprintf( "Try %u failed... exceeded max_tries (%u) so not going to retry", $try_count, $self->max_tries ) );
                    $retry = 0;
                }
            }
        }
    }while( $retry );

    $self->log->trace( "Last response:\n", Dump( $response ) ) if $self->log->is_trace;
    if( not $response->is_success ){
	$self->log->logdie( "API Error: http status:".  $response->code .' '.  $response->message . ' Content: ' . $response->content);
    }
    if( $response->decoded_content ){
        return decode_json( encode( 'utf8', $response->decoded_content ) );
    }
    return;
}


1;

=back

=head1 COPYRIGHT

Copyright 2015, Robin Clarke 

=head1 AUTHOR

Robin Clarke <robin@robinclarke.net>

Jeremy Falling <projects@falling.se>

