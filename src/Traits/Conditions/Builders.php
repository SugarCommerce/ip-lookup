<?php
/**
 * Condition builders
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Traits\Conditions;

use SugarCommerce\Conditions\Helpers\Geo as GeoOptions;
use SugarCommerce\Conditions\Operators;
use SugarCommerce\Geo\Countries;

/**
 * Trait Builders
 *
 * The shapes a condition takes in the rule builder -- yes/no, a number, a
 * text, tags, a choice, a country -- so each provider's list is one line
 * per condition.
 *
 * @since 1.0.0
 */
trait Builders {

	/**
	 * A yes/no condition.
	 *
	 * @param string   $group       The group in the builder.
	 * @param string   $label       The label.
	 * @param string   $description What it means.
	 * @param callable $compare     Gives the answer, or null for none.
	 * @param string[] $required    Arguments without which it is skipped.
	 *
	 * @return array
	 */
	private static function boolean( string $group, string $label, string $description, callable $compare, array $required = array() ): array {
		return array(
			'label'         => $label,
			'group'         => $group,
			'type'          => 'boolean',
			'description'   => $description,
			'compare_value' => $compare,
			'required_args' => $required,
		);
	}

	/**
	 * A number condition.
	 *
	 * @param string   $group       The group.
	 * @param string   $label       The label.
	 * @param string   $description What it means.
	 * @param callable $compare     Gives the number, or null for none.
	 * @param int      $example     The placeholder.
	 * @param bool     $percent     Whether it is held to 0-100.
	 *
	 * @return array
	 */
	private static function number( string $group, string $label, string $description, callable $compare, int $example, bool $percent = true ): array {
		return array(
			'label'         => $label,
			'group'         => $group,
			'type'          => 'number',
			/* translators: %d: an example number. */
			'placeholder'   => sprintf( __( 'e.g. %d', 'sugarcommerce' ), $example ),
			'min'           => 0,
			'step'          => 1,
			'description'   => $description,
			'compare_value' => $compare,
			'required_args' => array(),
		) + ( $percent ? array( 'max' => 100 ) : array() );
	}

	/**
	 * A text condition.
	 *
	 * @param string   $group       The group.
	 * @param string   $label       The label.
	 * @param string   $description What it means.
	 * @param callable $compare     Gives the text, or null for none.
	 *
	 * @return array
	 */
	private static function text( string $group, string $label, string $description, callable $compare ): array {
		return array(
			'label'         => $label,
			'group'         => $group,
			'type'          => 'text',
			'description'   => $description,
			'compare_value' => $compare,
			'required_args' => array(),
		);
	}

	/**
	 * A condition matched against a typed list, exactly.
	 *
	 * @param string   $group       The group.
	 * @param string   $label       The label.
	 * @param string   $description What it means.
	 * @param callable $compare     Gives the value or values, or null for none.
	 *
	 * @return array
	 */
	private static function tags( string $group, string $label, string $description, callable $compare ): array {
		return array(
			'label'         => $label,
			'group'         => $group,
			'type'          => 'tags',
			'operators'     => Operators::tags_exact(),
			'description'   => $description,
			'compare_value' => $compare,
			'required_args' => array(),
		);
	}

	/**
	 * A condition matched against a list of choices.
	 *
	 * @param string         $group       The group.
	 * @param string         $label       The label.
	 * @param string         $description What it means.
	 * @param array|callable $options     The choices, as value and label.
	 * @param callable       $compare     Gives the value, or null for none.
	 *
	 * @return array
	 */
	private static function choice( string $group, string $label, string $description, array|callable $options, callable $compare ): array {
		return array(
			'label'         => $label,
			'group'         => $group,
			'type'          => 'select',
			'multiple'      => true,
			'options'       => $options,
			'operators'     => Operators::collection_any_none(),
			'description'   => $description,
			'compare_value' => $compare,
			'required_args' => array(),
		);
	}

	/**
	 * A country condition.
	 *
	 * @param string   $group   The group.
	 * @param callable $compare Gives the code, or null for none.
	 *
	 * @return array
	 */
	private static function country( string $group, callable $compare ): array {
		return self::choice(
			$group,
			__( 'Country', 'sugarcommerce' ),
			__( 'The country the address is in. Useful beside the billing country, or for a second opinion on the visitor\'s.', 'sugarcommerce' ),
			fn () => GeoOptions::get_country_options(),
			function ( array $args ) use ( $compare ): ?string {
				$code = $compare( $args );

				return null === $code ? null : strtoupper( (string) $code );
			}
		);
	}

	/**
	 * The continents, as choices.
	 *
	 * @return array<array{value: string, label: string}>
	 */
	private static function continents(): array {
		$options = array();

		foreach ( Countries::get_continent_codes() as $code => $name ) {
			$options[] = array(
				'value' => $code,
				'label' => $name,
			);
		}

		return $options;
	}

	/**
	 * Values as choices.
	 *
	 * @param string[] $values The values.
	 * @param string[] $labels Their labels, if not the values themselves.
	 *
	 * @return array<array{value: string, label: string}>
	 */
	private static function options( array $values, array $labels = array() ): array {
		$options = array();

		foreach ( array_values( $values ) as $i => $value ) {
			$options[] = array(
				'value' => $value,
				'label' => $labels[ $i ] ?? $value,
			);
		}

		return $options;
	}
}
