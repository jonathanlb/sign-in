<?php
/**
 * Require authentication to view WordPress content.
 *
 * @package sign-in
 * @version 0.0.2
 */

/*
Plugin Name: sign-in
Plugin URI: https://github.com/jonathanlb
Description: Provide authenticated access to WP content.
Version: 0.0.2
Author: Jonathan Bredin
Author URI: https://bredin.org
License: https://www.gnu.org/licenses/gpl-3.0.txt GPLv3
*/

// Make sure we don't expose any info if called directly.
if ( ! function_exists( 'add_action' ) ) {
	echo 'Do not call plugins directly.';
	exit;
}

require 'vendor/autoload.php';
define( 'SIGN_IN__PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
require_once SIGN_IN__PLUGIN_DIR . 'class-sign-in.php';

register_activation_hook( __FILE__, array( 'Sign_In', 'plugin_activation' ) );
register_deactivation_hook( __FILE__, array( 'Sign_In', 'plugin_deactivation' ) );

add_action( 'init', array( 'Sign_In', 'init' ) );
