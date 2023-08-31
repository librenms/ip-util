<?php
/**
 * IPv4.php
 *
 * IPv4 parsing class
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @package    LibreNMS
 * @link       http://librenms.org
 * @copyright  2017 Tony Murray
 * @author     Tony Murray <murraytony@gmail.com>
 */

namespace LibreNMS\Util;

use LibreNMS\Exceptions\InvalidIpException;

class IPv4 extends IP implements \Iterator
{
    private $current;
    private $networkLongIp;

    /**
     * IPv4 constructor.
     * @param $ipv4
     * @throws InvalidIpException
     */
    public function __construct($ipv4)
    {
        $this->host_bits = 32;
        list($this->ip, $this->cidr) = $this->extractCidr($ipv4);

        if (!self::isValid($this->ip)) {
            throw new InvalidIpException("$ipv4 is not a valid ipv4 address");
        }

        $this->networkLongIp = $this->calculateNetworkAddress($this->ip, $this->cidr);
    }

    /**
     * Check if the supplied IP is valid.
     * @param string $ipv4
     * @param bool $exclude_reserved Exclude reserved IP ranges.
     * @return bool
     */
    public static function isValid($ipv4, $exclude_reserved = false)
    {
        $filter = FILTER_FLAG_IPV4;
        if ($exclude_reserved) {
            $filter |= FILTER_FLAG_NO_RES_RANGE;
        }

        return filter_var($ipv4, FILTER_VALIDATE_IP, $filter) !== false;
    }

    /**
     * Convert an IPv4 network mask to a bit mask.  For example: 255.255.255.0 -> 24
     * @param string $netmask
     * @return int
     */
    public static function netmask2cidr($netmask)
    {
        $long = ip2long($netmask);
        $base = ip2long('255.255.255.255');
        return (int)(32 - log(($long ^ $base) + 1, 2));
    }

    /**
     * Returns the netmask of this IP address. For example: 255.255.255.0
     * @return string
     */
    public function getNetmask()
    {
        return long2ip($this->cidr2long($this->cidr));
    }

    /**
     * Convert an IPv4 bit mask to a long. Generally used with long2ip() or bitwise operations.
     * @return int
     */
    private function cidr2long($cidr)
    {
        return -1 << (32 - (int)$cidr);
    }

    /**
     * Check if this IP address is contained inside the network.
     * @param string $network should be in cidr format.
     * @return mixed
     */
    public function inNetwork($network)
    {
        list($net, $cidr) = $this->extractCidr($network);
        if (!self::isValid($net)) {
            return false;
        }

        $mask = $this->cidr2long($cidr);
        return ((ip2long($this->ip) & $mask) == (ip2long($net) & $mask));
    }

    /**
     * Get the network address of this IP
     * @param int $cidr if not given will use the cidr stored with this IP
     * @return string
     */
    public function getNetworkAddress($cidr = null)
    {
        if (is_null($cidr) || $cidr == $this->cidr) {
            return long2ip($this->networkLongIp);
        }

        return long2ip($this->calculateNetworkAddress($this->ip, $cidr));
    }

    /**
     * Convert this IP to an snmp index hex encoded
     *
     * @return string
     */
    public function toSnmpIndex()
    {
        return (string)$this->ip;
    }


    /**
     * Get the long of the network address for the given IP and cidr.
     *
     * @param string $ip
     * @param int $cidr
     * @return int
     */
    protected function calculateNetworkAddress($ip, $cidr)
    {
        return ip2long($ip) & $this->cidr2long($cidr);
    }

    /**
     * Extract an address from a cidr, assume a host is given if it does not contain /
     * Handle netmasks in addition to cidr
     *
     * @param string $ip
     * @return array [$ip, $cidr]
     */
    protected function extractCidr($ip)
    {
        $parts = explode('/', $ip, 2);

        if (isset($parts[1])) {
            if (strpos($parts[1], '.') !== false) {
                // could be a netmask instead of cidr
                $parts[1] = self::netmask2cidr($parts[1]);
            }
        } else {
            $parts[1] = $this->host_bits;
        }

        return $parts;
    }

    // --- Iterable Methods ---
    public function current()
    {
        return long2ip($this->current);
    }

    public function next()
    {
        $this->current++;
    }

    public function key()
    {
        return $this->current;
    }

    public function valid()
    {
        if ($this->cidr == 32) {
            return $this->current === $this->networkLongIp;
        }

        if ($this->cidr == 31) {

            return $this->current === $this->networkLongIp || $this->current === ($this->networkLongIp + 1);
        }

        $max = $this->networkLongIp - $this->cidr2long($this->cidr) - 1;

        return $this->current > $this->networkLongIp && $this->current < $max;
    }

    public function rewind()
    {
        $this->current = $this->cidr > 30
            ? $this->networkLongIp
            : $this->networkLongIp + 1;

    }
}
