<?php
/**
 * Handle the business logic for the sign-in plugin.
 *
 * @package    sign-in
 * @author     Jonathan Bredin <bredin@acm.org>
 * @license    https://www.gnu.org/licenses/gpl-3.0.txt GNU/GPLv3
 * @link       https://github.com/jonathanlb/sign-in
 * @version    0.0.5
 * @since      0.0.1
 */

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\Credentials\CredentialProvider;

define( 'LOGOUT_SHORTCODE', 'sign_in_logout' );
define( 'SHORTCODE_PREFIX', 'sign_in_require_auth' );
define( 'TOKEN_EXPIRY_SECONDS', 14000 );

define( 'SI_COOKIE_DOMAIN', parse_url( get_site_url() )['host'] );
define( 'SI_COOKIE_PATH', '/' );
define( 'SI_COOKIE_SALT', 'FwAlpiSjsb' );
define( 'AUTH_TOKEN_COOKIE_NAME', 'sign_in_auth_token_' . SI_COOKIE_SALT );

define( 'SI_URL_LOGIN_KEY', 'login_msg' );
define( 'SI_LOGIN_INVALID_EMAIL', 'invalid_email' );
define( 'SI_LOGIN_PASSWORD_INCORRECT', 'password_incorrect' );
define( 'SI_LOGIN_PASSWORD_RESET_REQUEST', 'password_reset_requested' );
define( 'SI_LOGIN_PASSWORD_RESET_SUCCESS', 'password_reset_success' );
define( 'SI_LOGIN_SERVER_AUTHENTICATION_FAILED', 'server_authentication_failed' );

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
	private static $version = '0.0.5';

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
		$url_vars = array( SI_URL_LOGIN_KEY );
		foreach ( $url_vars as $var ) {
			$wp->add_query_var( $var );
		}

		add_action( 'admin_post_sign_in_auth', array( 'Sign_In', 'handle_login_post' ) );
		add_action( 'admin_post_nopriv_sign_in_auth', array( 'Sign_In', 'handle_login_post' ) );
		add_action( 'admin_post_sign_in_logout', array( 'Sign_In', 'handle_logout_post' ) );
		add_action( 'admin_post_nopriv_sign_in_logout', array( 'Sign_In', 'handle_logout_post' ) );
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
			__( 'Cognito App Client ID' ),
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
			error_log( 'No email or password: ' . $email . ' ' . $password );
			return null;
		}

		$client_id    = $aws_opts['client_id'] ?? null;
		$user_pool_id = $aws_opts['user_pool_id'] ?? null;
		if ( null === $client_id || null === $user_pool_id ) {
			error_log( 'No client id or user pool id: ' . $client_id . ' ' . $user_pool_id );
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
				error_log( 'No such user: ' . $email );
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
			error_log( 'Authentication error: ' . $e->getMessage() . ' for user ' . $email );
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

		// Prevent caching to respect login status.
		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			define( 'DONOTCACHEPAGE', true );
		} elseif ( ! DONOTCACHEPAGE ) {
			error_log( 'sign-in: cannot prevent caching for ' . get_permalink() );
		}

		$aws_opts = self::get_aws_opts( $shortcode );

		// check login status
		if ( isset( $_COOKIE[ AUTH_TOKEN_COOKIE_NAME ] ) ) {
			$token = filter_var( wp_unslash( $_COOKIE[ AUTH_TOKEN_COOKIE_NAME ] ), FILTER_UNSAFE_RAW );
			if ( self::validate_token( $token, $aws_opts ) ) {
				return self::render_authenticated_content( $shortcode, $content );
			}
		}

		// not authenticated, determine error/welcome message.
		$login_msg = 'Please log in:';
		if ( isset( $_GET[ SI_URL_LOGIN_KEY ] ) ) {
			switch ( $_GET[ SI_URL_LOGIN_KEY ] ) {
				case SI_LOGIN_SERVER_AUTHENTICATION_FAILED:
					$login_msg = 'Login redirect failed. Please try again:';
					break;
				case SI_LOGIN_PASSWORD_INCORRECT:
					$login_msg = 'User name or password incorrect.';
					break;
				case SI_LOGIN_PASSWORD_RESET_SUCCESS:
					$login_msg = 'Check your email for temporary password.';
					break;
				case SI_LOGIN_INVALID_EMAIL:
					$login_msg = 'Invalid email address.';
					break;
				case SI_LOGIN_PASSWORD_RESET_REQUEST:
					$login_msg = 'Password reset requested. Check your email for the reset code.';
					break;
				default:
					$login_msg = 'Please log in...';
					break;
			}
		}

		// XXX pass in aws_opts?
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

	public static function handle_login_post() {
		$url_parts = parse_url( wp_get_referer() );
		$slug      = $url_parts['path'];
		if ( ! isset( $_POST['sign_in_auth_nonce'] )
			|| ! wp_verify_nonce( $_POST['sign_in_auth_nonce'], 'sign_in_auth' )
		) {
			error_log( 'login failed nonce check' );
			wp_redirect( $slug . '?' . SI_URL_LOGIN_KEY . '=' . SI_LOGIN_SERVER_AUTHENTICATION_FAILED, status: 302, x_redirect_by: false );
			exit( 'Login security check failed.' );
		}

		$user_name = '';
		if ( isset( $_POST['user_name'] ) ) {
			$user_name = sanitize_text_field( $_POST['user_name'] );
		}
		$forgot_password = null;
		if ( isset( $_POST['password_forgot'] ) ) {
				$forgot_password = sanitize_text_field( $_POST['password_forgot'] );
		}
		$password = '';
		if ( isset( $_POST['password'] ) ) {
				$password = sanitize_text_field( $_POST['password'] );
		}
		$new_password = '';
		if ( isset( $_POST['new_password'] ) ) {
				$new_password = sanitize_text_field( $_POST['new_password'] );
		}

		$aws_opts = self::get_aws_opts( '' ); // XXX how to pass in options from post? nonce?
		if ( $new_password !== '' ) {
			// handle new password request
			if ( filter_var( $user_name, FILTER_VALIDATE_EMAIL ) ) {
				if ( self::reset_password( $aws_opts, $user_name, $new_password, $password ) ) {
					$token = self::authenticate_user( $user_name, $new_password, $aws_opts );
					if ( ! setcookie( AUTH_TOKEN_COOKIE_NAME, $token, time() + TOKEN_EXPIRY_SECONDS, SI_COOKIE_PATH, SI_COOKIE_DOMAIN ) ) { // XXX be strategic
						error_log( 'Failed to set cookie during password reset for user ' . $user_name );
					}
					wp_redirect( $slug, status: 302, x_redirect_by: false );
					exit();
				} else {
					wp_redirect( $slug . '?' . SI_URL_LOGIN_KEY . '=password_reset_request_failed', status: 302, x_redirect_by: false );
					exit();
				}
			} else {
				wp_redirect( $slug . '?' . SI_URL_LOGIN_KEY . '=password_reset_request_failed', status: 302, x_redirect_by: false );
				exit();
			}
		} elseif ( $forgot_password === 'yes' ) {
			if ( ! setcookie( AUTH_TOKEN_COOKIE_NAME, '', time() - TOKEN_EXPIRY_SECONDS, SI_COOKIE_PATH, SI_COOKIE_DOMAIN ) ) {
				error_log( 'Failed to reset cookie during password reset request for user ' . $user_name );
			}

			if ( filter_var( $user_name, FILTER_VALIDATE_EMAIL ) ) {
				if ( self::request_reset_password( $aws_opts, $user_name ) ) {
					wp_redirect( $slug . '?' . SI_URL_LOGIN_KEY . '=password_reset_requested', status: 302, x_redirect_by: false );
					exit();
				} else {
					wp_redirect( $slug . '?' . SI_URL_LOGIN_KEY . '=password_reset_request_failed', status: 302, x_redirect_by: false );
					exit();
				}
			} else {
				wp_redirect( $slug . '?' . SI_URL_LOGIN_KEY . '=invalid_email' );
				exit();
			}
		}

		$token = self::authenticate_user( $user_name, $password, $aws_opts );
		if ( null !== $token ) {
			if ( ! setcookie( AUTH_TOKEN_COOKIE_NAME, $token, time() + TOKEN_EXPIRY_SECONDS, SI_COOKIE_PATH, SI_COOKIE_DOMAIN ) ) { // XXX be strategic
				error_log( 'Failed to set cookie during authentication for user ' . $user_name );
			}
			wp_redirect( $slug, status: 302, x_redirect_by: false );
			exit();
		} else {
			if ( ! setcookie( AUTH_TOKEN_COOKIE_NAME, '', time() - TOKEN_EXPIRY_SECONDS, SI_COOKIE_PATH, SI_COOKIE_DOMAIN ) ) {
				error_log( 'Failed to reset cookie during failed authentication for user ' . $user_name );
			}
			wp_redirect( $slug . '?' . SI_URL_LOGIN_KEY . '=password_incorrect', status: 302, x_redirect_by: false );
			exit();
		}
	}

	public static function handle_logout_post() {
		$url_parts = parse_url( wp_get_referer() );
		$slug      = $url_parts['path'];
		if ( ! setcookie( AUTH_TOKEN_COOKIE_NAME, '', time() - TOKEN_EXPIRY_SECONDS, SI_COOKIE_PATH, SI_COOKIE_DOMAIN ) ) {
			error_log( 'Failed to reset cookie during logout for user ' . $_POST['user_name'] );
		}
		wp_redirect( $slug, status: 302, x_redirect_by: false );
		exit();
	}

	/**
	 * Respond to plugin_activation events by writing default settings.
	 */
	public static function plugin_activation() {
		$options = get_option( 'sign_in_settings' );
		if ( false === $options ) {
			$options = array();
		}

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
	 * Get the plugin version number.
	 */
	public static function get_version() {
		return self::$version;
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
	action='<?php echo admin_url( 'admin-post.php' ); ?>'
	method='post'>

	<input type="hidden" name="action" value="sign_in_auth" readonly />
		<?php wp_nonce_field( 'sign_in_auth', 'sign_in_auth_nonce' ); ?>

	<div class="sign-in-error"><b><?php echo esc_html( $error_msg ); ?></b></div>
	<div class="sign-in-label-input-pair">
		<label for="user_name_wp_sign_in">Email:</label>
		<input
			type="email"
			id="user_name_wp_sign_in"
			name="user_name"
			value=""
			autocomplete="username"
			required="required"
		/>
	</div>
	<div class="sign-in-label-input-pair" id="password_div_wp_sign_in">
		<label for="password_wp_sign_in">
			<?php str_starts_with( $error_msg, 'Password reset' ) ? esc_html_e( 'Temporary ', 'text-domain' ) : ''; ?>
			Password:</label>
		<input
			type="password"
			id="password_wp_sign_in"
			name="password"
			value=""
			autocomplete="current-password"
		/>
	</div>

		<?php if ( str_starts_with( $error_msg, 'Password reset' ) ) : ?> 
		<div class="sign-in-label-input-pair" id="new_password_div_wp_sign_in">
			<label for="new_password_wp_sign_in">New Password:</label>
			<input
				type="password"
				id="new_password_wp_sign_in"
				name="new_password"
				value=""
				minlength="8"
				pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*\W|_).{8,}"
				title="Must contain at least one number, one uppercase and lowercase letter, one special character, and at least 8 or more characters"
				required="required"
				autocomplete="new-password"
			/>
		</div>
	<?php endif; ?>

	<div class="sign-in-label-checkbox-pair">
		<label for="password_forgot_wp_sign_in">Forgot Password:</label>
		<input
			type="checkbox"
			id="password_forgot_wp_sign_in"
			name="password_forgot"
			value="no"
			onchange="wp_sign_in_handle_password_forgot_change(this)"
		/>
		<hr>
		<i>A password reset code will be sent to your email.</i>
	</div>
		<input type="submit" value="Log In" />
</form>
<script>
	let wp_sign_in_password_pair_display = "flex";

	function wp_sign_in_handle_password_forgot_change(checkbox) {
		if (checkbox.checked) {
			checkbox.value = "yes";
			let div = document.getElementById("password_div_wp_sign_in");
			wp_sign_in_password_pair_display = div.style.display;
			div.style.display = "none";

			div = document.getElementById("password_div_wp_sign_in");
			if (div) {
				div.style.display = "none";
			}
		} else {
			checkbox.value = "no";
			let div = document.getElementById("password_div_wp_sign_in");
			div.style.display = wp_sign_in_password_pair_display;

			div = document.getElementById("new_password_div_wp_sign_in");
			if (div) {
				div.style.display = "none";
			}
		}
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
			action='<?php echo admin_url( 'admin-post.php' ); ?>'
			method='post'>

			<input type="hidden" name="action" value="sign_in_logout" readonly />
			<input type="submit" value="Log Out" />
		</form>
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
	 * Perform password reset request for user, triggering a verification code
	 * sent via email, sms, etc.
	 *
	 * @param object $aws_opts AWS configuration options.
	 * @param string $user_name the user name (email).
	 * @return bool true if reset successful.
	 */
	public static function request_reset_password( $aws_opts, $user_name ) {
		try {
			$cognito    = self::get_identity_provider_client( $aws_opts );
			$reset_opts = array(
				'ClientId' => $aws_opts['client_id'],
				'Username' => $user_name,
			);
			$cognito->forgotPassword( $reset_opts );
			return true;
		} catch ( Exception $e ) {
			// e.g. user's email not verified
			error_log( 'password reset error for ' . $user_name . ' : ' . $e->getMessage() );
			return false;
		}
	}



	/**
	 * Perform password reset for user, given validation code and new password.
	 *
	 * @param object $aws_opts AWS configuration options.
	 * @param string $user_name the user name (email).
	 * @param string $new_password the new password, which should have already been checked for strength.
	 * @param string $validation_code the validation code sent to user to pass along to AWS.
	 *
	 * @return bool true if reset successful.
	 */
	public static function reset_password( $aws_opts, $user_name, $new_password, $validation_code ) {
		try {
			$cognito    = self::get_identity_provider_client( $aws_opts );
			$reset_opts = array(
				'ClientId'         => $aws_opts['client_id'],
				'Username'         => $user_name,
				'ConfirmationCode' => $validation_code,
				'Password'         => $new_password,
			);
			$cognito->confirmForgotPassword( $reset_opts );
			return true;
		} catch ( Exception $e ) {
			error_log( 'password reset error: ' . $user_name . ' : ' . $e->getMessage() );
			return false;
		}
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
			error_log( 'Invalid token: ' . $e->getMessage() );
			return false;
		}

		return false;
	}
}