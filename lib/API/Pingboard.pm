package API::Pingboard;
# ABSTRACT: API interface to Pingboard
use Moose;
use MooseX::Params::Validate;
use MooseX::WithCache;
use LWP::UserAgent;
use HTTP::Request;
use HTTP::Headers;
use JSON::MaybeXS;
use YAML;
use Encode;

our $VERSION = 0.003;

=head1 NAME

API::Pingboard

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

=item access_token

Required.

=cut
has 'access_token' => (
    is          => 'ro',
    isa         => 'Str',
    required    => 1,
    );

# TODO Username and password login not working yet
=item password


=cut
has 'password' => (
    is          => 'ro',
    isa         => 'Str',
    required    => 0,
    );

=item username


=cut
has 'username' => (
    is          => 'ro',
    isa         => 'Str',
    required    => 0,
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

=item pingboard_api_url

Required.

=cut
has 'pingboard_api_url' => (
    is		=> 'ro',
    isa		=> 'Str',
    required	=> 1,
    default     => 'https://app.pingboard.com/api/v2/',
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

has 'default_headers' => (
    is		=> 'ro',
    isa		=> 'HTTP::Headers',
    required	=> 1,
    lazy	=> 1,
    builder	=> '_build_default_headers',
    );

sub _build_user_agent {
    my $self = shift;
    $self->log->debug( "Building useragent" );
    my $ua = LWP::UserAgent->new(
	keep_alive	=> 1,
        timeout         => $self->timeout,
    );
    return $ua;
}

sub _build_default_headers {
    my $self = shift;
    my $h = HTTP::Headers->new();
    $h->header( 'Content-Type'	=> "application/json" );
    $h->header( 'Accept'	=> "application/json" );
    # Only oauth works for now
    $h->header( 'Authorization' => "Bearer " . $self->access_token );
    return $h;
}


=back

=head1 METHODS

=over 4

=item init

Create the user agent.  As these are built lazily, initialising manually can avoid
errors thrown when building them later being silently swallowed in try/catch blocks.

=cut

sub init {
    my $self = shift;
    my $ua = $self->user_agent;
}

=item get_users

=over 4

=item id

The user id to get

=cut

sub get_users {
    my ( $self, %params ) = validated_hash(
        \@_,
        id	    => { isa    => 'Int', optional => 1 },
        limit       => { isa    => 'Int', optional => 1 },
        page_size   => { isa    => 'Int', optional => 1 },
	);
    $params{field}  = 'users';
    $params{path}   = 'users' . ( $params{id} ? '/' . $params{id} : '' );
    delete( $params{id} );
    return $self->_paged_request_from_api( %params );
}

=item get_groups

=over 4

=item id (optional)

The group id to get

=cut

sub get_groups {
    my ( $self, %params ) = validated_hash(
        \@_,
        id	    => { isa    => 'Int', optional => 1 },
        limit       => { isa    => 'Int', optional => 1 },
        page_size   => { isa    => 'Int', optional => 1 },
	);
    $params{field}  = 'groups';
    $params{path}   = 'groups' . ( $params{id} ? '/' . $params{id} : '' );
    delete( $params{id} );
    return $self->_paged_request_from_api( %params );
}

=item get_custom_fields

=over 4

=item id (optional)

The resource id to get

=cut

sub get_custom_fields {
    my ( $self, %params ) = validated_hash(
        \@_,
        id	    => { isa    => 'Int', optional => 1 },
        limit       => { isa    => 'Int', optional => 1 },
        page_size   => { isa    => 'Int', optional => 1 },
	);
    $params{field}  = 'custom_fields';
    $params{path}   = 'custom_fields' . ( $params{id} ? '/' . $params{id} : '' );
    delete( $params{id} );
    return $self->_paged_request_from_api( %params );
}

=item get_linked_accounts

=over 4

=item id

The resource id to get

=cut

sub get_linked_accounts {
    my ( $self, %params ) = validated_hash(
        \@_,
        id	=> { isa    => 'Int'},
	);
    $params{field}  = 'linked_accounts';
    $params{path}   = 'linked_accounts/' . $params{id};
    delete( $params{id} );
    return $self->_paged_request_from_api( %params );
}

=item get_linked_account_providers

=over 4

=item id (optional)

The resource id to get

=cut

sub get_linked_account_providers {
    my ( $self, %params ) = validated_hash(
        \@_,
        id	    => { isa    => 'Int', optional => 1 },
        limit       => { isa    => 'Int', optional => 1 },
        page_size   => { isa    => 'Int', optional => 1 },
	);
    $params{field}  = 'linked_account_providers';
    $params{path}   = 'linked_account_providers' . ( $params{id} ? '/' . $params{id} : '' );
    delete( $params{id} );
    return $self->_paged_request_from_api( %params );
}

=item get_statuses

=over 4

=item id (optional)

The resource id to get

=cut

sub get_statuses {
    my ( $self, %params ) = validated_hash(
        \@_,
        id	    => { isa    => 'Int', optional => 1 },
        limit       => { isa    => 'Int', optional => 1 },
        page_size   => { isa    => 'Int', optional => 1 },
	);
    $params{field}  = 'statuses';
    $params{path}   = 'statuses' . ( $params{id} ? '/' . $params{id} : '' );
    delete( $params{id} );
    return $self->_paged_request_from_api( %params );
}


=item clear_cache_object_id

Clears an object from the cache.

=over 4

=item user_id

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
        $response = $self->_request_from_api(
            method      => $params{method},
            path        => $params{path} . ( $params{path} =~ m/\?/ ? '&' : '?' ) . 'page=' . $page . '&page_size=' . $params{page_size},
            );
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
        fields  => { isa => 'HashRef', optional => 1 },
    );
    my $url;
    if( $params{uri} ){
        $url = $params{uri};
    }elsif( $params{path} ){
        $url =  $self->pingboard_api_url . $params{path};
    }else{
        $self->log->logdie( "Cannot request without either a path or uri" );
    }

    my $request = HTTP::Request->new(
        $params{method},
        $url,
        $params{headers} || $self->default_headers,
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

