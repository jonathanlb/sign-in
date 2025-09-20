<?php
/**
 * Require authentication to view WordPress content.
 *
 * @package cog-log-ing
 * @version 0.0.1
 */

/*
Plugin Name: cog-log-ing
Plugin URI: https://github.com/jonathanlb
Description: Provide authenticated access to WP content.
Version: 0.0.1
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
define( 'COG_LOG_ING__PLUGIN_DIR', plugin_dir_path( __FILE__ ) );

register_activation_hook( __FILE__, array( 'Cog_Log_Ing', 'plugin_activation' ) );
register_deactivation_hook( __FILE__, array( 'Cog_Log_Ing', 'plugin_deactivation' ) );

require_once COG_LOG_ING__PLUGIN_DIR . 'class-cog-log-ing.php';

add_action( 'init', array( 'Cog_Log_Ing', 'init' ) );
