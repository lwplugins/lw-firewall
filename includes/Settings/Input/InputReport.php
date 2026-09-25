<?php
/**
 * Result of parsing a batch of submitted settings.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Settings\Input;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Valid values, per-field errors, and the keys that were set aside
 * (pinned in wp-config.php, or not a setting at all).
 */
final class InputReport {

	/**
	 * Constructor.
	 *
	 * @param array<string, mixed>              $values  Parsed values of the valid fields.
	 * @param array<string, array<int, string>> $errors  Messages per invalid field.
	 * @param array<int, string>                $locked  Submitted keys pinned by a constant.
	 * @param array<int, string>                $unknown Submitted keys that are not settings.
	 */
	public function __construct(
		private array $values,
		private array $errors,
		private array $locked,
		private array $unknown
	) {
	}

	/**
	 * Parsed values of the valid fields.
	 *
	 * @return array<string, mixed>
	 */
	public function values(): array {
		return $this->values;
	}

	/**
	 * Messages per invalid field.
	 *
	 * @return array<string, array<int, string>>
	 */
	public function errors(): array {
		return $this->errors;
	}

	/**
	 * Submitted keys pinned by a wp-config.php constant.
	 *
	 * @return array<int, string>
	 */
	public function locked(): array {
		return $this->locked;
	}

	/**
	 * Submitted keys that are not settings.
	 *
	 * @return array<int, string>
	 */
	public function unknown(): array {
		return $this->unknown;
	}

	/**
	 * Whether any field was refused.
	 *
	 * @return bool
	 */
	public function has_errors(): bool {
		return [] !== $this->errors;
	}
}
