<?php
/**
 * Settings field registry.
 *
 * @package Datametric\LoginShield
 */

namespace Datametric\LoginShield\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	die( '-1' );
}

use Datametric\LoginShield\Support\Options;

/**
 * A tiny registry that lets modules declare settings tabs and fields.
 *
 * Rendering, sanitization and saving all happen centrally here, so every field
 * is escaped and sanitized in exactly one audited place (important for the
 * WordPress.org review).
 */
class Settings {

	/**
	 * Registered tabs: slug => [label, priority, render].
	 *
	 * @var array<string, array>
	 */
	protected static $tabs = array();

	/**
	 * Registered fields: tab slug => list of field definitions.
	 *
	 * @var array<string, array<int, array>>
	 */
	protected static $fields = array();

	/**
	 * Register a settings tab.
	 *
	 * @param string        $slug     Tab slug.
	 * @param string        $label    Human label.
	 * @param int           $priority Sort order (lower first).
	 * @param callable|null $render   Optional custom renderer; when null, the
	 *                                tab renders its registered fields as a form.
	 *
	 * @return void
	 */
	public static function add_tab( $slug, $label, $priority = 20, $render = null ) {
		self::$tabs[ $slug ] = array(
			'label'    => $label,
			'priority' => $priority,
			'render'   => $render,
		);
	}

	/**
	 * Register a field under a tab.
	 *
	 * Field args: key, type (text|number|checkbox|textarea|select), label,
	 * description, default, options (for select), min, max, placeholder.
	 *
	 * @param string $tab  Tab slug.
	 * @param array  $args Field definition.
	 *
	 * @return void
	 */
	public static function add_field( $tab, array $args ) {
		if ( empty( $args['key'] ) ) {
			return;
		}

		$args = wp_parse_args(
			$args,
			array(
				'type'        => 'text',
				'label'       => '',
				'description' => '',
				'default'     => '',
				'options'     => array(),
				'min'         => null,
				'max'         => null,
				'placeholder' => '',
			)
		);

		self::$fields[ $tab ][] = $args;
	}

	/**
	 * All registered tabs, sorted by priority.
	 *
	 * @return array<string, array>
	 */
	public static function tabs() {
		$tabs = self::$tabs;

		uasort(
			$tabs,
			static function ( $a, $b ) {
				return $a['priority'] <=> $b['priority'];
			}
		);

		return $tabs;
	}

	/**
	 * Fields registered for a tab.
	 *
	 * @param string $tab Tab slug.
	 *
	 * @return array<int, array>
	 */
	public static function fields_for( $tab ) {
		return isset( self::$fields[ $tab ] ) ? self::$fields[ $tab ] : array();
	}

	/**
	 * Render all fields for a tab as form-table rows.
	 *
	 * @param string $tab Tab slug.
	 *
	 * @return void
	 */
	public static function render_fields( $tab ) {
		$fields = self::fields_for( $tab );

		if ( empty( $fields ) ) {
			return;
		}

		echo '<table class="form-table" role="presentation">';
		foreach ( $fields as $field ) {
			self::render_field( $field );
		}
		echo '</table>';
	}

	/**
	 * Render a single field row.
	 *
	 * @param array $field Field definition.
	 *
	 * @return void
	 */
	public static function render_field( array $field ) {
		$key   = $field['key'];
		$id    = 'dmls_' . $key;
		$value = Options::get( $key, $field['default'] );

		echo '<tr>';
		echo '<th scope="row"><label for="' . esc_attr( $id ) . '">' . esc_html( $field['label'] ) . '</label></th>';
		echo '<td>';

		switch ( $field['type'] ) {
			case 'checkbox':
				echo '<label><input type="checkbox" id="' . esc_attr( $id ) . '" name="' . esc_attr( $key ) . '" value="1" ' . checked( (bool) $value, true, false ) . ' /> ';
				echo esc_html( $field['description'] ) . '</label>';
				break;

			case 'number':
				echo '<input type="number" id="' . esc_attr( $id ) . '" name="' . esc_attr( $key ) . '" value="' . esc_attr( (string) $value ) . '" class="small-text"';
				if ( null !== $field['min'] ) {
					echo ' min="' . esc_attr( (string) $field['min'] ) . '"';
				}
				if ( null !== $field['max'] ) {
					echo ' max="' . esc_attr( (string) $field['max'] ) . '"';
				}
				echo ' />';
				if ( $field['description'] ) {
					echo '<p class="description">' . esc_html( $field['description'] ) . '</p>';
				}
				break;

			case 'textarea':
				echo '<textarea id="' . esc_attr( $id ) . '" name="' . esc_attr( $key ) . '" rows="5" class="large-text code" placeholder="' . esc_attr( $field['placeholder'] ) . '">' . esc_textarea( (string) $value ) . '</textarea>';
				if ( $field['description'] ) {
					echo '<p class="description">' . esc_html( $field['description'] ) . '</p>';
				}
				break;

			case 'select':
				echo '<select id="' . esc_attr( $id ) . '" name="' . esc_attr( $key ) . '">';
				foreach ( (array) $field['options'] as $opt_value => $opt_label ) {
					echo '<option value="' . esc_attr( (string) $opt_value ) . '" ' . selected( (string) $value, (string) $opt_value, false ) . '>' . esc_html( $opt_label ) . '</option>';
				}
				echo '</select>';
				if ( $field['description'] ) {
					echo '<p class="description">' . esc_html( $field['description'] ) . '</p>';
				}
				break;

			case 'text':
			default:
				echo '<input type="text" id="' . esc_attr( $id ) . '" name="' . esc_attr( $key ) . '" value="' . esc_attr( (string) $value ) . '" class="regular-text" placeholder="' . esc_attr( $field['placeholder'] ) . '" />';
				if ( $field['description'] ) {
					echo '<p class="description">' . esc_html( $field['description'] ) . '</p>';
				}
				break;
		}

		echo '</td></tr>';
	}

	/**
	 * Sanitize a raw submitted value according to its field definition.
	 *
	 * @param array $field Field definition.
	 * @param mixed $raw   Raw (already wp_unslash'ed) value, or null when absent.
	 *
	 * @return mixed
	 */
	public static function sanitize_value( array $field, $raw ) {
		switch ( $field['type'] ) {
			case 'checkbox':
				return ! empty( $raw );

			case 'number':
				$n = is_scalar( $raw ) ? intval( $raw ) : intval( $field['default'] );
				if ( null !== $field['min'] ) {
					$n = max( (int) $field['min'], $n );
				}
				if ( null !== $field['max'] ) {
					$n = min( (int) $field['max'], $n );
				}
				return $n;

			case 'textarea':
				return sanitize_textarea_field( is_scalar( $raw ) ? (string) $raw : '' );

			case 'select':
				$val = is_scalar( $raw ) ? (string) $raw : '';
				return array_key_exists( $val, (array) $field['options'] ) ? $val : (string) $field['default'];

			case 'text':
			default:
				return sanitize_text_field( is_scalar( $raw ) ? (string) $raw : '' );
		}
	}
}
