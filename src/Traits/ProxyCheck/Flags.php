<?php
/**
 * ProxyCheck query flags
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Traits\ProxyCheck;

use WP_Error;

/**
 * Trait Flags
 *
 * The query flags ProxyCheck is asked with: how hard to look for VPNs,
 * whether to send the network, the risk, the port, when it was last seen,
 * how many days back a detection counts, and the dashboard tag.
 *
 * @since 1.0.0
 */
trait Flags {

	/**
	 * The query flags sent with every check.
	 *
	 * @var array<string, int|string>
	 */
	private array $parameters = array(
		'vpn'           => 0,
		'asn'           => 0,
		'node'          => 0,
		'time'          => 0,
		'inf'           => 0,
		'risk'          => 0,
		'port'          => 0,
		'seen'          => 0,
		'days'          => 7,
		'tag'           => '',
		'ver'           => 2,
		'mask'          => 0,
		'query_tagging' => 0,
	);

	/**
	 * Every query flag, as it will be sent.
	 *
	 * @since 1.0.0
	 *
	 * @return array<string, int|string>
	 */
	public function get_parameters(): array {
		return $this->parameters;
	}

	/**
	 * How hard to look for VPNs: 0 off, 1 on, 2 with the operator's name, 3
	 * with its policies.
	 *
	 * @since 1.0.0
	 *
	 * @param int $mode 0 to 3.
	 *
	 * @return static|WP_Error
	 */
	public function set_vpn( int $mode ): static|WP_Error {
		if ( $mode < 0 || $mode > 3 ) {
			return $this->error( 'invalid_vpn_mode', __( 'The VPN mode is 0 to 3.', 'sugarcommerce' ) );
		}

		$this->parameters['vpn'] = $mode;

		return $this;
	}

	/**
	 * The VPN mode.
	 *
	 * @since 1.0.0
	 *
	 * @return int
	 */
	public function get_vpn(): int {
		return (int) $this->parameters['vpn'];
	}

	/**
	 * Ask for the network, the location and the provider.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $enable Whether to.
	 *
	 * @return static
	 */
	public function set_asn( bool $enable ): static {
		return $this->flag( 'asn', $enable );
	}

	/**
	 * Whether the network is asked for.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function get_asn(): bool {
		return (bool) $this->parameters['asn'];
	}

	/**
	 * Ask which node answered.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $enable Whether to.
	 *
	 * @return static
	 */
	public function set_node( bool $enable ): static {
		return $this->flag( 'node', $enable );
	}

	/**
	 * Whether the node is asked for.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function get_node(): bool {
		return (bool) $this->parameters['node'];
	}

	/**
	 * Ask how long the query took.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $enable Whether to.
	 *
	 * @return static
	 */
	public function set_time( bool $enable ): static {
		return $this->flag( 'time', $enable );
	}

	/**
	 * Whether the query time is asked for.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function get_time(): bool {
		return (bool) $this->parameters['time'];
	}

	/**
	 * Ask for real-time inference, which catches proxies not yet listed.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $enable Whether to.
	 *
	 * @return static
	 */
	public function set_inf( bool $enable ): static {
		return $this->flag( 'inf', $enable );
	}

	/**
	 * Whether inference is asked for.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function get_inf(): bool {
		return (bool) $this->parameters['inf'];
	}

	/**
	 * Ask for a risk score: 0 off, 1 the score, 2 the score and attack
	 * history.
	 *
	 * @since 1.0.0
	 *
	 * @param int $level 0 to 2.
	 *
	 * @return static|WP_Error
	 */
	public function set_risk( int $level ): static|WP_Error {
		if ( $level < 0 || $level > 2 ) {
			return $this->error( 'invalid_risk_level', __( 'The risk level is 0 to 2.', 'sugarcommerce' ) );
		}

		$this->parameters['risk'] = $level;

		return $this;
	}

	/**
	 * The risk level.
	 *
	 * @since 1.0.0
	 *
	 * @return int
	 */
	public function get_risk(): int {
		return (int) $this->parameters['risk'];
	}

	/**
	 * Ask which port the proxy was seen on.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $enable Whether to.
	 *
	 * @return static
	 */
	public function set_port( bool $enable ): static {
		return $this->flag( 'port', $enable );
	}

	/**
	 * Whether the port is asked for.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function get_port(): bool {
		return (bool) $this->parameters['port'];
	}

	/**
	 * Ask when the proxy was last seen.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $enable Whether to.
	 *
	 * @return static
	 */
	public function set_seen( bool $enable ): static {
		return $this->flag( 'seen', $enable );
	}

	/**
	 * Whether last seen is asked for.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function get_seen(): bool {
		return (bool) $this->parameters['seen'];
	}

	/**
	 * How many days back a detection counts.
	 *
	 * @since 1.0.0
	 *
	 * @param int $days At least 1.
	 *
	 * @return static|WP_Error
	 */
	public function set_days( int $days ): static|WP_Error {
		if ( $days < 1 ) {
			return $this->error( 'invalid_days', __( 'Days must be at least 1.', 'sugarcommerce' ) );
		}

		$this->parameters['days'] = $days;

		return $this;
	}

	/**
	 * How many days back a detection counts.
	 *
	 * @since 1.0.0
	 *
	 * @return int
	 */
	public function get_days(): int {
		return (int) $this->parameters['days'];
	}

	/**
	 * Tag every query, so the dashboard shows where it came from. With no
	 * tag set, the site's name is the tag.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $enable Whether to.
	 *
	 * @return static
	 */
	public function set_query_tagging( bool $enable ): static {
		$this->flag( 'query_tagging', $enable );

		if ( $enable && '' === $this->parameters['tag'] && function_exists( 'get_bloginfo' ) ) {
			$this->parameters['tag'] = sanitize_text_field( (string) get_bloginfo( 'name' ) );
		}

		return $this;
	}

	/**
	 * Whether queries are tagged.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function get_query_tagging(): bool {
		return (bool) $this->parameters['query_tagging'];
	}

	/**
	 * The tag queries are sent with.
	 *
	 * @since 1.0.0
	 *
	 * @param string $tag The tag.
	 *
	 * @return static
	 */
	public function set_tag( string $tag ): static {
		$this->parameters['tag'] = $tag;

		return $this;
	}

	/**
	 * The tag queries are sent with.
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public function get_tag(): string {
		return (string) $this->parameters['tag'];
	}

	/**
	 * Turn a 0/1 flag on or off.
	 *
	 * @param string $name   The flag.
	 * @param bool   $enable Whether it is on.
	 *
	 * @return static
	 */
	private function flag( string $name, bool $enable ): static {
		$this->parameters[ $name ] = $enable ? 1 : 0;

		return $this;
	}
}
