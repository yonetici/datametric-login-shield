<?php
/**
 * Pro module: custom login-page branding.
 *
 * @package Datametric\LoginShield
 */

namespace Datametric\LoginShield\Modules\Branding;

if ( ! defined( 'ABSPATH' ) ) {
	die( '-1' );
}

use Datametric\LoginShield\Container;
use Datametric\LoginShield\Contracts\ModuleInterface;
use Datametric\LoginShield\Admin\Settings;
use Datametric\LoginShield\Support\Options;

/**
 * Restyles the WordPress login screen: logo, colours and custom CSS. Uses core
 * login hooks only — no changes to the free plugin required.
 */
class BrandingModule implements ModuleInterface {

	/**
	 * {@inheritDoc}
	 */
	public function id() {
		return 'pro-branding';
	}

	/**
	 * {@inheritDoc}
	 */
	public function is_pro() {
		return false;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param Container $container Shared container.
	 */
	public function register( Container $container ) {}

	/**
	 * {@inheritDoc}
	 */
	public function boot() {
		if ( is_admin() ) {
			$this->register_settings();
		}

		add_action( 'login_head', array( $this, 'output_css' ) );
		add_filter( 'login_headerurl', array( $this, 'logo_link' ) );
		add_filter( 'login_headertext', array( $this, 'logo_text' ) );
	}

	/**
	 * Register the Branding settings tab.
	 *
	 * @return void
	 */
	private function register_settings() {
		Settings::add_tab( 'branding', __( 'Branding', 'datametric-login-shield' ), 28 );

		Settings::add_field(
			'branding',
			array(
				'key'         => 'pro_brand_logo',
				'type'        => 'text',
				'label'       => __( 'Logo URL', 'datametric-login-shield' ),
				'description' => __( 'URL of an image to show above the login form.', 'datametric-login-shield' ),
				'placeholder' => 'https://example.com/logo.png',
			)
		);

		Settings::add_field(
			'branding',
			array(
				'key'         => 'pro_brand_logo_link',
				'type'        => 'text',
				'label'       => __( 'Logo link', 'datametric-login-shield' ),
				'description' => __( 'Where the logo links to (defaults to your site home).', 'datametric-login-shield' ),
			)
		);

		Settings::add_field(
			'branding',
			array(
				'key'   => 'pro_brand_bg',
				'type'  => 'text',
				'label' => __( 'Background colour (hex)', 'datametric-login-shield' ),
				'placeholder' => '#1e2a4a',
			)
		);

		Settings::add_field(
			'branding',
			array(
				'key'   => 'pro_brand_accent',
				'type'  => 'text',
				'label' => __( 'Button / accent colour (hex)', 'datametric-login-shield' ),
				'placeholder' => '#12b5a5',
			)
		);

		Settings::add_field(
			'branding',
			array(
				'key'         => 'pro_brand_css',
				'type'        => 'textarea',
				'label'       => __( 'Custom CSS', 'datametric-login-shield' ),
				'description' => __( 'Advanced: extra CSS applied to the login page.', 'datametric-login-shield' ),
			)
		);
	}

	/**
	 * Output the branding CSS inside the login <head>.
	 *
	 * @return void
	 */
	public function output_css() {
		$logo   = esc_url( (string) Options::get( 'pro_brand_logo', '' ) );
		$bg     = sanitize_hex_color( (string) Options::get( 'pro_brand_bg', '' ) );
		$accent = sanitize_hex_color( (string) Options::get( 'pro_brand_accent', '' ) );
		$custom = (string) Options::get( 'pro_brand_css', '' );

		$css = '';

		if ( '' !== $logo ) {
			$css .= '#login h1 a{background-image:url(' . $logo . ');background-size:contain;width:100%;height:80px}';
		}
		if ( $bg ) {
			$css .= 'body.login{background:' . $bg . '}';
		}
		if ( $accent ) {
			$css .= '.wp-core-ui .button-primary{background:' . $accent . ';border-color:' . $accent . ';box-shadow:none;text-shadow:none}';
			$css .= '.login #nav a:hover,.login #backtoblog a:hover,.login a:hover{color:' . $accent . '}';
		}
		if ( '' !== trim( $custom ) ) {
			// Admin-authored CSS; strip tags to prevent breaking out of <style>.
			$css .= wp_strip_all_tags( $custom );
		}

		if ( '' === $css ) {
			return;
		}

		echo "<style id='dmlsp-branding'>" . $css . "</style>\n"; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- URLs/colors sanitized above; custom CSS stripped of tags.
	}

	/**
	 * Filter the logo link.
	 *
	 * @param string $url Default URL.
	 *
	 * @return string
	 */
	public function logo_link( $url ) {
		$link = trim( (string) Options::get( 'pro_brand_logo_link', '' ) );

		return '' !== $link ? esc_url( $link ) : $url;
	}

	/**
	 * Filter the logo title text to the site name.
	 *
	 * @param string $text Default text.
	 *
	 * @return string
	 */
	public function logo_text( $text ) {
		if ( '' !== (string) Options::get( 'pro_brand_logo', '' ) ) {
			return wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		}

		return $text;
	}
}
