<?php
/**
 * Tests for Sign_In plugin.
 *
 * @package    sign-in
 * @author     Jonathan Bredin <bredin@acm.org>
 * @license    https://www.gnu.org/licenses/gpl-3.0.txt GNU/GPLv3
 * @link       https://github.com/jonathanlb/sign-in
 * @version    0.0.4
 * @since      0.0.2
 */

require_once __DIR__ . '/../class-sign-in.php';

/**
 * Unit tests for Sign_In class.
 */
class Sign_In_Test extends WP_UnitTestCase {
	/**
	 * Ensure module activation.
	 */
	public function setUp(): void {
		parent::setUp();
		Sign_In::plugin_activation();
	}

	/**
	 * Ensure module deactivation.
	 */
	public function tearDown(): void {
		parent::tearDown();
		Sign_In::plugin_deactivation();
	}

	/**
	 * Ensure that we can set credentials path outside plugin directory.
	 */
	public function test_can_configure_global_credentials(): void {
		$options                         = get_option( 'sign_in_settings' );
		$options['aws_credentials_path'] = '/Users/myuser/.aws/';
		update_option( 'sign_in_settings', $options );

		$opts = Sign_In::get_aws_opts( 'sign_in_require_auth' );
		$this->assertEquals( '/Users/myuser/.aws/', $opts['credentials'] );
	}

	/**
	 * Ensure that we can set credentials path inside plugin directory.
	 */
	public function test_defaults_to_local_credentials(): void {
		$options                         = get_option( 'sign_in_settings' );
		$options['aws_credentials_path'] = 'local-aws';
		update_option( 'sign_in_settings', $options );

		$opts = Sign_In::get_aws_opts( 'sign_in_require_auth' );
		$this->assertEquals( SIGN_IN__PLUGIN_DIR . 'local-aws', $opts['credentials'] );
	}

	/**
	 * Ensure that default credentials path is plugin directory.
	 */
	public function test_defaults_credentials(): void {
		$opts = Sign_In::get_aws_opts( 'sign_in_require_auth' );
		$this->assertEquals( SIGN_IN__PLUGIN_DIR . 'credentials', $opts['credentials'] );
	}

	/**
	 * Ensure that we can extract the shortcode from content.
	 */
	public function test_get_shortcode_from_content(): void {
		$content   = 'Some content [sign_in_require_auth] more content';
		$shortcode = Sign_In::get_shortcode_from_content( $content );
		$this->assertEquals( 'sign_in_require_auth', $shortcode );
	}

	/**
	 * Ensure that we can extract shortcode and its options from content.
	 */
	public function test_get_shortcode_options_from_content(): void {
		$content   = 'Some content [sign_in_require_auth aws_profile="editor"  aws_client_id="234" cognito_user_pool_id="tuv" ] more content';
		$shortcode = Sign_In::get_shortcode_from_content( $content );
		// make sure to preserve leading and trailing spaces, as we want to be able to quickly replace page content on authentication.
		$this->assertEquals( 'sign_in_require_auth aws_profile="editor"  aws_client_id="234" cognito_user_pool_id="tuv" ', $shortcode );
	}

	/**
	 * Make sure that we can get default options when shortcode doesn't specify them.
	 */
	public function test_get_default_options_from_shortcode(): void {
		$shortcode = 'sign_in_require_auth';
		$opts      = Sign_In::get_aws_opts( $shortcode );

		$this->assertEquals( 'default', $opts['profile'] );
		$this->assertEquals( 'us-east-2', $opts['region'] );
		$this->assertEquals( '', $opts['client_id'] );
		$this->assertEquals( '', $opts['user_pool_id'] );
	}

	/**
	 * Make sure that we can get overriding profile when shortcode specifies it.
	 */
	public function test_get_profile_from_shortcode(): void {
		$shortcode = ' sign_in_require_auth  aws_profile="custom" ';
		$opts      = Sign_In::get_aws_opts( $shortcode );
		$this->assertEquals( 'custom', $opts['profile'] );
	}

	/**
	 * Make sure that we can get overriding region when shortcode specifies it.
	 */
	public function test_get_region_from_shortcode(): void {
		$shortcode = 'sign_in_require_auth aws_region="custom"';
		$opts      = Sign_In::get_aws_opts( $shortcode );
		$this->assertEquals( 'custom', $opts['region'] );
	}

	/**
	 * Make sure that we can get overriding client_id when shortcode specifies it.
	 */
	public function test_get_client_id_from_shortcode(): void {
		$shortcode = 'sign_in_require_auth aws_client_id="custom"';
		$opts      = Sign_In::get_aws_opts( $shortcode );
		$this->assertEquals( 'custom', $opts['client_id'] );
	}

	/**
	 * Make sure that we can get overriding user_pool_id when shortcode specifies it.
	 */
	public function test_get_user_pool_id_from_shortcode(): void {
		$shortcode = 'sign_in_require_auth cognito_user_pool_id="custom"';
		$opts      = Sign_In::get_aws_opts( $shortcode );
		$this->assertEquals( 'custom', $opts['user_pool_id'] );
	}
}
