<?php
/**
 * Field Renderer Trait.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Settings;

use LightweightPlugins\Firewall\Options;

/**
 * Trait for rendering form fields.
 */
trait FieldRendererTrait {

	/**
	 * Render a checkbox field.
	 *
	 * @param array{name: string, label: string, description?: string} $args Field arguments.
	 * @return void
	 */
	protected function render_checkbox_field( array $args ): void {
		$name  = $args['name'];
		$label = $args['label'] ?? '';
		$desc  = $args['description'] ?? '';
		$value = Options::get( $name );

		printf(
			'<label><input type="checkbox" name="%s[%s]" value="1" %s /> %s</label>',
			esc_attr( Options::OPTION_NAME . '_options' ),
			esc_attr( $name ),
			checked( $value, true, false ),
			esc_html( $label )
		);

		if ( $desc ) {
			printf( '<p class="description">%s</p>', esc_html( $desc ) );
		}
	}

	/**
	 * Render a select field.
	 *
	 * @param array{name: string, label: string, options: array<string, string>, description?: string} $args Field arguments.
	 * @return void
	 */
	protected function render_select_field( array $args ): void {
		$name    = $args['name'];
		$label   = $args['label'] ?? '';
		$choices = $args['options'] ?? [];
		$desc    = $args['description'] ?? '';
		$value   = Options::get( $name );

		if ( $label ) {
			printf( '<label for="lw-fw-%s">%s</label><br/>', esc_attr( $name ), esc_html( $label ) );
		}

		printf(
			'<select id="lw-fw-%s" name="%s[%s]">',
			esc_attr( $name ),
			esc_attr( Options::OPTION_NAME . '_options' ),
			esc_attr( $name )
		);

		foreach ( $choices as $opt_value => $opt_label ) {
			printf(
				'<option value="%s" %s>%s</option>',
				esc_attr( $opt_value ),
				selected( $value, $opt_value, false ),
				esc_html( $opt_label )
			);
		}

		echo '</select>';

		if ( $desc ) {
			printf( '<p class="description">%s</p>', esc_html( $desc ) );
		}
	}

	/**
	 * Render a number field.
	 *
	 * @param array{name: string, label: string, min?: int, max?: int, step?: int, description?: string} $args Field arguments.
	 * @return void
	 */
	protected function render_number_field( array $args ): void {
		$name  = $args['name'];
		$label = $args['label'] ?? '';
		$min   = $args['min'] ?? 1;
		$max   = $args['max'] ?? 9999;
		$step  = $args['step'] ?? 1;
		$desc  = $args['description'] ?? '';
		$value = (int) Options::get( $name );

		if ( $label ) {
			printf( '<label for="lw-fw-%s">%s</label><br/>', esc_attr( $name ), esc_html( $label ) );
		}

		printf(
			'<input type="number" id="lw-fw-%s" name="%s[%s]" value="%d" min="%d" max="%d" step="%d" class="small-text" />',
			esc_attr( $name ),
			esc_attr( Options::OPTION_NAME . '_options' ),
			esc_attr( $name ),
			esc_attr( (string) $value ),
			esc_attr( (string) $min ),
			esc_attr( (string) $max ),
			esc_attr( (string) $step )
		);

		if ( $desc ) {
			printf( '<p class="description">%s</p>', esc_html( $desc ) );
		}
	}

	/**
	 * Render a textarea field.
	 *
	 * @param array{name: string, label?: string, rows?: int, description?: string} $args Field arguments.
	 * @return void
	 */
	protected function render_textarea_field( array $args ): void {
		$name  = $args['name'];
		$label = $args['label'] ?? '';
		$rows  = $args['rows'] ?? 6;
		$desc  = $args['description'] ?? '';
		$value = Options::get( $name );

		// Convert arrays to newline-separated text.
		if ( is_array( $value ) ) {
			$value = implode( "\n", $value );
		}

		if ( $label ) {
			printf( '<label for="lw-fw-%s">%s</label><br/>', esc_attr( $name ), esc_html( $label ) );
		}

		printf(
			'<textarea id="lw-fw-%s" name="%s[%s]" rows="%d" class="large-text code">%s</textarea>',
			esc_attr( $name ),
			esc_attr( Options::OPTION_NAME . '_options' ),
			esc_attr( $name ),
			esc_attr( (string) $rows ),
			esc_textarea( (string) $value )
		);

		if ( $desc ) {
			printf( '<p class="description">%s</p>', esc_html( $desc ) );
		}
	}
}
