<?php
/**
 * Outcome of parsing one raw setting value.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Settings\Input;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Either a clean option value or the list of reasons it was refused.
 */
final class ParseResult {

	/**
	 * Parsed value (null when invalid).
	 *
	 * @var mixed
	 */
	private mixed $value;

	/**
	 * Human-readable error messages.
	 *
	 * @var array<int, string>
	 */
	private array $errors;

	/**
	 * Constructor.
	 *
	 * @param mixed              $value  Parsed value.
	 * @param array<int, string> $errors Error messages.
	 */
	private function __construct( mixed $value, array $errors ) {
		$this->value  = $value;
		$this->errors = $errors;
	}

	/**
	 * A valid value.
	 *
	 * @param mixed $value Parsed value.
	 * @return self
	 */
	public static function ok( mixed $value ): self {
		return new self( $value, [] );
	}

	/**
	 * A refused value.
	 *
	 * @param array<int, string> $errors Error messages (at least one).
	 * @return self
	 */
	public static function fail( array $errors ): self {
		return new self( null, array_values( $errors ) );
	}

	/**
	 * The parsed value, or null when invalid.
	 *
	 * @return mixed
	 */
	public function value(): mixed {
		return $this->value;
	}

	/**
	 * Error messages; empty when valid.
	 *
	 * @return array<int, string>
	 */
	public function errors(): array {
		return $this->errors;
	}

	/**
	 * Whether the value was accepted.
	 *
	 * @return bool
	 */
	public function is_valid(): bool {
		return [] === $this->errors;
	}
}
