<?php
/**
 * Handle the business logic for the sign-in plugin.
 *
 * @package    sign-in
 * @author     Jonathan Bredin <bredin@acm.org>
 * @license    https://www.gnu.org/licenses/gpl-3.0.txt GNU/GPLv3
 * @link       https://github.com/jonathanlb/sign-in
 * @version    0.0.4
 * @since      0.0.1
 */

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\Credentials\CredentialProvider;

define( 'COOKIE_SALT', 'FwAlpiSjsb' );
define( 'AUTH_TOKEN_COOKIE_NAME', 'sign_in_auth_token_' . COOKIE_SALT );
define( 'LOGOUT_SHORTCODE', 'sign_in_logout' );
define( 'PASSWORD_COOKIE_NAME', 'sign_in_password_' . COOKIE_SALT );
define( 'SHORTCODE_PREFIX', 'sign_in_require_auth' );
define( 'TOKEN_EXPIRY_SECONDS', 14000 );
define( 'USER_NAME_COOKIE_NAME', 'sign_in_user_name_' . COOKIE_SALT );
define( 'USER_NAME_EXPIRY_SECONDS', 120 ); // just long enough to do the redirect after login form submission.

/**
 * Handle AWS configuration, user validation, and replacing
 * protected content with login form.
 */
class Sign_In {
	/**
	 * AWS SDK configuration options -- region, credentials alias, etc.
	 *
	 * @var object Lazily-generated AWS configuration from user-settings DB.
	 */
	private static $aws_opts = null;

	/**
	 * Signal initialization flag.
	 *
	 * @var bool To prevent multiple initializations.
	 */
	private static $initialized = false;

	/**
	 * Plugin version number.
	 *
	 * @var string unused locally version number.
	 */
	private static $version = '0.0.3';

	/**
	 * Initialize the plugin
	 *
	 * @since 0.0.1
	 */
	public static function init() {
		if ( self::$initialized ) {
			return;
		}

		self::$initialized = true;
		add_action( 'admin_init', array( 'Sign_In', 'admin_init' ) );
		add_action( 'admin_menu', array( 'Sign_In', 'admin_menu' ) );

		global $wp;
		$url_vars = array( 'password', 'token', 'user_name' );
		foreach ( $url_vars as $var ) {
			$wp->add_query_var( $var );
		}

		add_filter( 'the_content', array( 'Sign_In', 'filter_protected_content' ) );
	}

	/**
	 * Respond to admin_init action.
	 */
	public static function admin_init() {
		/**
		 *  A shorthand to escape out title.
		 */
		function aws_settings_callback() {
			esc_html_e( 'AWS Settings' );
		}

		/**
		 * Retrieve an option value and populate it to input field.
		 *
		 * @param array $text_input Text-input attributes.
		 */
		function text_input_callback( $text_input ) {
			$option_group = $text_input['option_group'];
			$option_id    = $text_input['option_id'];
			$option_name  = "{$option_group}[{$option_id}]";
			$options      = get_option( $option_group );
			$option_value = $options[ $option_id ] ?? '';
			?>
			<input type="text" size="32" id="<?php echo esc_attr( $option_id ); ?>"
		name="<?php echo esc_attr( $option_name ); ?>"
		value="<?php echo esc_attr( $option_value ); ?>" />
			<?php
		}

		add_settings_section(
			'aws_settings_section',
			__( 'AWS Settings' ),
			'aws_settings_callback',
			'sign_in_settings'
		);
		add_settings_field(
			'aws_credentials_path',
			__( 'Path to credentials file' ),
			'text_input_callback',
			'sign_in_settings',
			'aws_settings_section',
			array(
				'label_for'    => 'aws_credentials_path',
				'option_group' => 'sign_in_settings',
				'option_id'    => 'aws_credentials_path',
			)
		);
		add_settings_field(
			'aws_credentials_profile',
			__( 'Credentials profile' ),
			'text_input_callback',
			'sign_in_settings',
			'aws_settings_section',
			array(
				'label_for'    => 'aws_credentials_profile',
				'option_group' => 'sign_in_settings',
				'option_id'    => 'aws_credentials_profile',
			)
		);
		add_settings_field(
			'aws_region',
			__( 'Region' ),
			'text_input_callback',
			'sign_in_settings',
			'aws_settings_section',
			array(
				'label_for'    => 'aws_region',
				'option_group' => 'sign_in_settings',
				'option_id'    => 'aws_region',
			)
		);
		add_settings_field(
			'aws_client_id',
			__( 'AWS Client ID' ),
			'text_input_callback',
			'sign_in_settings',
			'aws_settings_section',
			array(
				'label_for'    => 'aws_client_id',
				'option_group' => 'sign_in_settings',
				'option_id'    => 'aws_client_id',
			)
		);
		add_settings_field(
			'cognito_user_pool_id',
			__( 'Cognito User Pool ID' ),
			'text_input_callback',
			'sign_in_settings',
			'aws_settings_section',
			array(
				'label_for'    => 'cognito_user_pool_id',
				'option_group' => 'sign_in_settings',
				'option_id'    => 'cognito_user_pool_id',
			)
		);
		add_settings_field(
			'aws_version',
			__( 'Version' ),
			'text_input_callback',
			'sign_in_settings',
			'aws_settings_section',
			array(
				'label_for'    => 'aws_version',
				'option_group' => 'sign_in_settings',
				'option_id'    => 'aws_version',
			)
		);

		register_setting( 'sign_in_settings', 'sign_in_settings' );
	}

	/**
	 * Respond to admin_menu action.
	 */
	public static function admin_menu() {
		add_submenu_page(
			'options-general.php',
			'sign-in Settings',
			'sign-in',
			'manage_options',
			'sign-in',
			array( 'Sign_In', 'render_settings_page' )
		);
	}

	/**
	 * Get AWS configuration options from the database.
	 *
	 * @param string $email used to log in.
	 * @param string $password user password.
	 * @param object $aws_opts AWS configuration options.
	 *
	 * @return string Authentication token or null if invalid credentials.
	 */
	private static function authenticate_user( $email, $password, $aws_opts ) {
		if ( null === $email || null === $password ) {
			return null;
		}

		$client_id    = $aws_opts['client_id'] ?? null;
		$user_pool_id = $aws_opts['user_pool_id'] ?? null;
		if ( null === $client_id || null === $user_pool_id ) {
			return null;
		}

		try {
			// Look up user name from email.
			$cognito         = self::get_identity_provider_client( $aws_opts );
			$email           = strtolower( $email );
			$list_users_args = array(
				'UserPoolId' => $user_pool_id,
				'Filter'     => "email = \"$email\"",
				'Limit'      => 1,
			);
			$result          = $cognito->ListUsers( $list_users_args );
			$users           = $result->get( 'Users' );
			if ( count( $users ) === 0 ) {
				echo '<script>console.error("No such user: ' . esc_js( $email ) . '")</script>';
				return null;
			}

			$user_name = $users[0]['Username'];
			$userpass  = array(
				'USERNAME' => $user_name,
				'PASSWORD' => $password,
			);
			$auth_args = array(
				'AuthFlow'       => 'USER_PASSWORD_AUTH',
				'ClientId'       => $client_id,
				'UserPoolId'     => $user_pool_id,
				'AuthParameters' => $userpass,
			);
			$result    = $cognito->InitiateAuth( $auth_args );
			return $result->get( 'AuthenticationResult' )['AccessToken'];
		} catch ( Exception $e ) {
			echo '<script>console.error("Authenticating error: ' . esc_js( $e->getMessage() ) . '")</script>';
			return null;
		}

		return null;
	}

	/**
	 * Remove Filter protected content.
	 *
	 * @param string $content the post content.
	 */
	public static function filter_protected_content( $content ) {
		$shortcode = self::get_shortcode_from_content( $content );
		if ( ! $shortcode ) {
			return $content;
		}

		$aws_opts = self::get_aws_opts( $shortcode );

		// Check if token is in URL and valid, removing the login shortcode if so,
		// otherwise redirect to the same page for login.
		if ( isset( $_COOKIE[ AUTH_TOKEN_COOKIE_NAME ] ) ) {
			$token = filter_var( wp_unslash( $_COOKIE[ AUTH_TOKEN_COOKIE_NAME ] ), FILTER_UNSAFE_RAW );
			if ( self::validate_token( $token, $aws_opts ) ) {
				return self::render_authenticated_content( $shortcode, $content );
			} else {
				unset( $_COOKIE[ AUTH_TOKEN_COOKIE_NAME ] );
				setcookie( AUTH_TOKEN_COOKIE_NAME, '', 1, '/' );
				wp_redirect( get_permalink( get_the_ID() ) );
				exit();
			}
		}

		// Check if user_name and password are in URL and valid.
		// If so, generate token and redirect.
		$user_name = '';
		$password  = '';
		if ( isset( $_COOKIE[ USER_NAME_COOKIE_NAME ] ) && isset( $_COOKIE[ PASSWORD_COOKIE_NAME ] ) ) {
			$user_name = urldecode( filter_var( wp_unslash( $_COOKIE[ USER_NAME_COOKIE_NAME ] ), FILTER_SANITIZE_EMAIL ) );
			$password  = urldecode( filter_var( wp_unslash( $_COOKIE[ PASSWORD_COOKIE_NAME ] ), FILTER_UNSAFE_RAW ) );
			if ( filter_var( $user_name, FILTER_VALIDATE_EMAIL ) === false ) {
				echo '<script>console.error("Invalid email: ' . esc_js( $user_name ) . '")</script>';
				$user_name = null;
			}

			// Clean up cookies.
			unset( $_COOKIE[ USER_NAME_COOKIE_NAME ] );
			unset( $_COOKIE[ PASSWORD_COOKIE_NAME ] );
			setcookie( USER_NAME_COOKIE_NAME, '', 1, '/' );
			setcookie( PASSWORD_COOKIE_NAME, '', 1, '/' );

			$token = self::authenticate_user( $user_name, $password, $aws_opts );
			if ( null !== $token ) {
				setcookie( AUTH_TOKEN_COOKIE_NAME, $token, time() + TOKEN_EXPIRY_SECONDS, '/' );
				$result = get_permalink( get_the_ID() );
				wp_redirect( $result );
				exit();
			}
		}

		// Otherwise, render login form with instruction or error message.
		$login_msg = 'Please log in';
		if ( $user_name || $password ) {
			$login_msg = 'Invalid login';
		}
		if ( '' === $aws_opts['client_id'] ) {
			$login_msg = 'Plugin not configured with AWS Client ID';
		} elseif ( '' === $aws_opts['user_pool_id'] ) {
			$login_msg = 'Plugin not configured with Cognito User Pool ID';
		}
		return self::render_unauthenticated_content( $content, $login_msg );
	}

	/**
	 * Get AWS configuration options from the database.
	 *
	 * @param string $shortcode the shortcode string triggering the request.
	 * Make sure to strip off the surrounding [ and ].
	 *
	 * @return object AWS configuration from user-settings DB.
	 */
	public static function get_aws_opts( $shortcode ) {
		$options = get_option( 'sign_in_settings' );

		$profile = $options['aws_credentials_profile'];
		if ( ! $profile ) {
			$profile = 'default';
		}
		$credentials_path = trim( $options['aws_credentials_path'] );
		if ( $credentials_path ) {
			if ( ! str_starts_with( $credentials_path, '/' ) ) {
				$credentials_path = SIGN_IN__PLUGIN_DIR . $credentials_path;
			}
		} else {
			// Do not default to home directory to exposed developer credentials, etc.
			$credentials_path = SIGN_IN__PLUGIN_DIR;
		}

		$aws_opts = array(
			'client_id'    => $options['aws_client_id'],
			'credentials'  => $credentials_path,
			'user_pool_id' => $options['cognito_user_pool_id'],
			'profile'      => $profile,
			'region'       => $options['aws_region'],
			'version'      => $options['aws_version'],
		);

		$overrides = shortcode_parse_atts( $shortcode );
		if ( isset( $overrides['aws_profile'] ) ) {
			$aws_opts['profile'] = $overrides['aws_profile'];
		}
		if ( isset( $overrides['aws_region'] ) ) {
			$aws_opts['region'] = $overrides['aws_region'];
		}
		if ( isset( $overrides['aws_client_id'] ) ) {
			$aws_opts['client_id'] = $overrides['aws_client_id'];
		}
		if ( isset( $overrides['cognito_user_pool_id'] ) ) {
			$aws_opts['user_pool_id'] = $overrides['cognito_user_pool_id'];
		}

		return $aws_opts;
	}

	/**
	 * Get Cognito Identity Provider client.
	 *
	 * @param object $aws_opts AWS configuration options used to create the client.
	 * @return CognitoIdentityProviderClient the Cognito client.
	 */
	public static function get_identity_provider_client( $aws_opts ) {
		$id_provider_client_opts                = array(
			'client_id'    => $aws_opts['client_id'],
			'user_pool_id' => $aws_opts['user_pool_id'],
			'region'       => $aws_opts['region'],
			'version'      => $aws_opts['version'],
		);
		$provider                               = CredentialProvider::ini( $aws_opts['profile'], $aws_opts['credentials'] );
		$provider                               = CredentialProvider::memoize( $provider );
		$id_provider_client_opts['credentials'] = $provider;
		return new CognitoIdentityProviderClient( $id_provider_client_opts );
	}

	/**
	 * Extract shortcode from content.
	 * Does not include surrounding [ and ], but does include the shortcode itself and preceeding and trailing whitespace.
	 *
	 * @param string $content the post content.
	 * @return string|null the shortcode found, or null if none.
	 */
	public static function get_shortcode_from_content( $content ) {
		$start_pos = strpos( $content, SHORTCODE_PREFIX );
		if ( ! $start_pos ) {
			return null;
		}

		$shortcode_end = strpos( $content, ']', $start_pos );
		if ( ! $shortcode_end ) {
			return null;
		}
		$shortcode = substr( $content, $start_pos, $shortcode_end - $start_pos );
		// don't trim the shortcode here, as we might need to wholesale replace/hide it in the webpage.
		return $shortcode;
	}

	/**
	 * Respond to plugin_activation events by writing default settings.
	 */
	public static function plugin_activation() {
		$options = get_option( 'sign_in_settings' );
		if ( ! isset( $options['aws_credentials_path'] ) ) {
			$options['aws_credentials_path'] = 'credentials';
		}
		if ( ! isset( $options['aws_credentials_profile'] ) ) {
			$options['aws_credentials_profile'] = 'default';
		}
		if ( ! isset( $options['aws_region'] ) ) {
			$options['aws_region'] = 'us-east-2';
		}
		if ( ! isset( $options['aws_version'] ) ) {
			$options['aws_version'] = 'latest';
		}
		if ( ! isset( $options['aws_client_id'] ) ) {
			$options['aws_client_id'] = '';
		}
		if ( ! isset( $options['cognito_user_pool_id'] ) ) {
			$options['cognito_user_pool_id'] = '';
		}

		add_option( 'sign_in_settings', $options );
	}

	/**
	 * Respond to plugin_deactivation events.
	 */
	public static function plugin_deactivation() {
		delete_option( 'sign_in_settings' );
	}

	/**
	 * Render the authenticated content.
	 *
	 * @param string $shortcode the shortcode string triggering the request.
	 * @param string $content the post content.
	 * @return string the content with login shortcode elided and the logout shortcode replaced with a button.
	 */
	public static function render_authenticated_content( $shortcode, $content ) {
		$result_content = str_replace( '[' . LOGOUT_SHORTCODE . ']', self::render_logout(), $content );
		return str_replace( '[' . $shortcode . ']', '', $result_content );
	}

	/**
	 * Display HTML login form that will redirect to the same page with filled in
	 * user_name and password parameters.
	 *
	 * @param string $error_msg message to display above the form.
	 */
	public static function render_login( $error_msg = '' ) {
		ob_start();
		?>
<link rel="stylesheet" href="<?php echo esc_html( plugin_dir_url( __FILE__ ) . 'style.css' ); ?>" />
<form class="sign-in-login"
	onsubmit="wp_sign_in_handle_submit(event);"
	action='<?php echo esc_html( get_permalink( get_the_ID() ) ); ?>'>
	<div class="sign-in-error"><?php echo esc_html( $error_msg ); ?></div>
	<div class="sign-in-label-input-pair">
		<label for="user_name_wp_sign_in">Email:</label>
		<input
			type="text"
			id="user_name_wp_sign_in"
			name="user_name"
			value=""
			autocomplete="username"
		/>
	</div>
	<div class="sign-in-label-input-pair">
		<label for="password_wp_sign_in">Password:</label>
		<input
			type="password"
			id="password_wp_sign_in"
			name="password"
			value=""
			autocomplete="current-password"
		/>
	</div>
	<div class="sign-in-label-input-pair">
		<input type="submit" value="Log In" />
	</div>
</form>
<script>
	function wp_sign_in_handle_submit(event) {
		event.preventDefault();
		const form = event.target;
		const user_name = form.user_name.value;
		const password = form.password.value;

		const expiryDate = new Date();
		expiryDate.setTime(expiryDate.getTime() + (<?php echo number_format( USER_NAME_EXPIRY_SECONDS ); ?> * 1000));
		const expires = "expires=" + expiryDate.toUTCString();

		document.cookie = "<?php echo esc_attr( USER_NAME_COOKIE_NAME ); ?>=" + encodeURIComponent(user_name) + ";" + expires + ";path=/";
		document.cookie = "<?php echo esc_attr( PASSWORD_COOKIE_NAME ); ?>=" + encodeURIComponent(password) + ";" + expires + ";path=/";
		window.location.href = form.action;
	}
</script>
		<?php
		return ob_get_clean();
	}

	/**
	 * Render the logout shortcode content.
	 *
	 * @return string the logout form HTML.
	 */
	public static function render_logout() {
		ob_start();
		?>
		<form class="sign-in-logout-form"
			onsubmit="wp_sign_out_handle_submit(event);"
			action='<?php echo esc_html( get_permalink( get_the_ID() ) ); ?>'>
			<input type="submit" value="Log Out" />
		</form>
		<script>
			function wp_sign_out_handle_submit(event) {
				event.preventDefault();
				const form = event.target;
				document.cookie = "<?php echo esc_attr( AUTH_TOKEN_COOKIE_NAME ); ?>=;expires=Thu, 01 Jan 1970 00:00:00 UTC;path=/";
				document.cookie = "<?php echo esc_attr( USER_NAME_COOKIE_NAME ); ?>=;expires=Thu, 01 Jan 1970 00:00:00 UTC;path=/";
				document.cookie = "<?php echo esc_attr( PASSWORD_COOKIE_NAME ); ?>=;expires=Thu, 01 Jan 1970 00:00:00 UTC;path=/";
				window.location.href = form.action;
			}
		</script>
		<?php
		return ob_get_clean();
	}

	/**
	 * Build the plugin settings page.
	 */
	public static function render_settings_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		?>
<div class="wrap">
	<h2><?php esc_html_e( 'Sign In Settings' ); ?></h2>

	<form method="post" action="options.php">
		<?php
			settings_fields( 'sign_in_settings' );
			do_settings_sections( 'sign_in_settings' );
			submit_button();
		?>
	</form>

</div><!-- /.wrap -->
		<?php
	}

	/**
	 * Render the unauthenticated content with login form.
	 *
	 * @param string $content the post content.
	 * @param string $login_msg message to display above the login form.
	 * @return string the content with login form replacing the protected content.
	 */
	public static function render_unauthenticated_content( $content, $login_msg ) {
		$start_pos = strpos( $content, SHORTCODE_PREFIX );
		$result    = substr( $content, 0, $start_pos - 1 ) . self::render_login( $login_msg );
		$result    = str_replace( '[' . LOGOUT_SHORTCODE . ']', '', $result );
		return $result;
	}

	/**
	 * Check if a token is signed and still valid.
	 *
	 * @param string $token the token to validate.
	 * @param object $aws_opts AWS configuration options.
	 * @return bool true if token is valid.
	 */
	public static function validate_token( $token, $aws_opts ) {
		if ( null === $token ) {
			return false;
		}

		try {
			$cognito = self::get_identity_provider_client( $aws_opts );
			$result  = $cognito->getUser( array( 'AccessToken' => $token ) );
			if ( isset( $result['Username'] ) ) {
				return true;
			}
		} catch ( Exception $e ) {
			echo '<script>console.error("Invalid token: ' . esc_js( $e->getMessage() ) . '")</script>';
			return false;
		}

		return false;
	}
}