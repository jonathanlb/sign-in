<?php
/**
 * Handle the business logic for the cog-log-ing plugin.
 *
 * @package    cog-log-ing
 * @author     Jonathan Bredin <bredin@acm.org>
 * @license    https://www.gnu.org/licenses/gpl-3.0.txt GNU/GPLv3
 * @link       https://github.com/jonathanlb
 * @since      0.0.1
 */

/**
 * Handle AWS configuration, user validation, and replacing
 * protected content with login form.
 */
class Cog_Log_Ing {
	/**
	 * AWS SDK configuration options -- region, credentials alias, etc.
	 *
	 * @var object Lazily-generated AWS configuration from user-settings DB.
	 */
	private static $aws_config = null;

	/**
	 * AWS Cognito client.
	 *
	 * @var object Lazily-generated Cognito client.
	 */
	private static $cognito_client = null;

	/**
	 * Signle initialization flag.
	 *
	 * @var bool To prevent multiple initializations.
	 */
	private static $initialized = false;

	/**
	 * Plugin version number.
	 *
	 * @var string unused locally version number.
	 */
	private static $version = '0.0.1';

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
		add_action( 'admin_init', array( 'Cog_Log_Ing', 'admin_init' ) );
		add_action( 'admin_menu', array( 'Cog_Log_Ing', 'admin_menu' ) );

		global $wp;
		$url_vars = array( 'password', 'token', 'user_name' );
		foreach ( $url_vars as $var ) {
			$wp->add_query_var( $var );
		}

		add_filter( 'the_content', array( 'Cog_Log_Ing', 'filter_protected_content' ) );
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
			'cog_log_ing_settings'
		);
		add_settings_field(
			'aws_credentials_path',
			__( 'Path to credentials file' ),
			'text_input_callback',
			'cog_log_ing_settings',
			'aws_settings_section',
			array(
				'label_for'    => 'aws_credentials_path',
				'option_group' => 'cog_log_ing_settings',
				'option_id'    => 'aws_credentials_path',
			)
		);
		add_settings_field(
			'aws_credentials_profile',
			__( 'Credentials profile' ),
			'text_input_callback',
			'cog_log_ing_settings',
			'aws_settings_section',
			array(
				'label_for'    => 'aws_credentials_profile',
				'option_group' => 'cog_log_ing_settings',
				'option_id'    => 'aws_credentials_profile',
			)
		);
		add_settings_field(
			'link_timeout',
			__( 'Link Timeout' ),
			'text_input_callback',
			'cog_log_ing_settings',
			'aws_settings_section',
			array(
				'label_for'    => 'link_timeout',
				'option_group' => 'cog_log_ing_settings',
				'option_id'    => 'link_timeout',
			)
		);
		add_settings_field(
			'aws_region',
			__( 'Region' ),
			'text_input_callback',
			'cog_log_ing_settings',
			'aws_settings_section',
			array(
				'label_for'    => 'aws_region',
				'option_group' => 'cog_log_ing_settings',
				'option_id'    => 'aws_region',
			)
		);
		add_settings_field(
			'aws_version',
			__( 'Version' ),
			'text_input_callback',
			'cog_log_ing_settings',
			'aws_settings_section',
			array(
				'label_for'    => 'aws_version',
				'option_group' => 'cog_log_ing_settings',
				'option_id'    => 'aws_version',
			)
		);

		register_setting( 'cog_log_ing_settings', 'cog_log_ing_settings' );
	}

	/**
	 * Respond to admin_menu action.
	 */
	public static function admin_menu() {
		add_submenu_page(
			'options-general.php',
			'cog-log-ing Settings',
			'cog-log-ing',
			'manage_options',
			'cog-log-ing',
			array( 'Cog_Log_Ing', 'render_settings_page' )
		);
	}

	/**
	 * Build an AWS SDK object from plugin options.
	 *
	 * @param array $aws_opts configuration to override global options.
	 */
	private static function create_aws_sdk( $aws_opts ) {
		$options    = get_option( 'cog_log_ing_settings' );
		$aws_config = array(
			'region'  => isset( $aws_opts['region'] ) ? $aws_opts['region'] : $options['aws_region'],
			'version' => $options['aws_version'],
		);

		$profile          = $options['aws_credentials_profile'];
		$credentials_path = $options['aws_credentials_path'];

		if ( $credentials_path ) {
			if ( ! str_starts_with( $credentials_path, '/' ) ) {
				$credentials_path = COG_LOG_ING__PLUGIN_DIR . $credentials_path;
			}
			$provider = CredentialProvider::ini( $profile, $credentials_path );
			$provider = CredentialProvider::memoize( $provider );

			$aws_config['credentials'] = $provider;
		} else {
			$aws_config['profile'] = $profile;
		}

		$sdk = new Aws\Sdk( $aws_config );
		return $sdk;
	}

	/**
	 * Provide a cognito client.
	 *
	 * @param array $aws_opts configuration to override global options.
	 */
	public static function cognito_client( $aws_opts ) {
		if ( self::$aws_config === $aws_opts && null !== self::$cognito_client ) {
			return self::$cognito_client;
		}

		self::$aws_config = $aws_opts;

		$aws_sdk              = self::create_aws_sdk( $aws_opts );
		self::$cognito_client = $aws_sdk->createCognitoIdentityProvider();
		return self::$cognito_client;
	}

	/**
	 * Remove Filter protected content.
	 *
	 * @param string $content the post content.
	 */
	public static function filter_protected_content( $content ) {
		$start_pos = strpos( $content, '[cogloging_require_auth' );
		if ( ! $start_pos ) {
			return $content;
		}

		// Check if token is in URL and valid.
		// TODO: validate token.
		$token = get_query_var( 'token', null );
		if ( 'xyz' === $token ) {
			$pattern = '/\[cogloging_require_auth[^\]]*\]/s';
			return preg_replace( $pattern, '', $content );
		} elseif ( null !== $token ) {
			wp_redirect( get_permalink( get_the_ID() ) );
			exit();
		}

		// Check if user_name and password are in URL and valid.
		// If so, generate token and redirect.
		$user_name = get_query_var( 'user_name', null );
		$password  = get_query_var( 'password', null );
		// TODO: validate user_name and password.
		if ( 'jonathan' === $user_name && 'secret' === $password ) {
			$result = get_permalink( get_the_ID() );
			wp_redirect( $result . '?token=xyz' );
			exit();
		}

		$login_msg = 'Please log in';
		if ( $user_name || $password ) {
			$login_msg = 'Invalid login';
		}
		$result = substr( $content, 0, $start_pos ) . self::render_login( $login_msg );

		return $result;
	}

	/**
	 * Respond to plugin_activation events by writing default settings.
	 */
	public static function plugin_activation() {
		$options = get_option( 'cog_log_ing_settings' );
		if ( ! isset( $options['aws_credentials_path'] ) ) {
			$options['aws_credentials_path'] = '';
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
		if ( ! isset( $options['link_timeout'] ) ) {
			$options['link_timeout'] = '+8 hours';
		}

		add_option( 'cog_log_ing_settings', $options );
	}

	/**
	 * Respond to plugin_deactivation events.
	 */
	public static function plugin_deactivation() {
		delete_option( 'cog_log_ing_settings' );
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
<form class="cog-log-ing-login"
	action='<?php echo esc_html( get_permalink( get_the_ID() ) ); ?>'>
	<div class="cog-log-ing-error"><?php echo esc_html( $error_msg ); ?></div>
	<div class="cog-log-ing-label-input-pair">
		<label for="user_name">Email:</label>
		<input
			type="text"
			id="user_name"
			name="user_name"
			value=""
			autocomplete="username"
		/>
	</div>
	<div class="cog-log-ing-label-input-pair">
		<label for="password">Password:</label>
		<input
			type="password"
			id="password"
			name="password"
			value=""
			autocomplete="current-password"
		/>
	</div>
	<div class="cog-log-ing-label-input-pair">
		<input type="submit" value="Log In" />
	</div>
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
	<h2><?php esc_html_e( 'Cog Log Ing Settings' ); ?></h2>

	<form method="post" action="options.php">
		<?php
			settings_fields( 'cog_log_ing_settings' );
			do_settings_sections( 'cog_log_ing_settings' );
			submit_button();
		?>
	</form>

</div><!-- /.wrap -->
		<?php
	}
}