[![CI](https://github.com/librenms/ip-util/actions/workflows/ci.yaml/badge.svg)](https://github.com/librenms/ip-util/actions/workflows/ci.yaml)

# IPUtil
IPv4 and IPv6 Address/Network parsing utility classes

Requirements PHP 5.6+

Does not require bcmath or gmp.

Built for use in [LibreNMS - Network Monitoring Software](https://librenms.org).

## Usage

#### Create a new IP instance
```php
try {
    $ip = new IP('192.168.1.1');
    // or
    $ip = IP::parse('192.168.1.1');
} catch (InvalidIpException $e) {
    //
}
```

#### Check if a given string is a valid IP
```php
IP::isValid('192.168.1.333');
```

You may specifically require IPv4 or IPv6 by using those classes directly:
```php
$ip = IPv4::parse('192.168.1.1');
$ip = IPv6::parse('2600::');

IPv4::isValid('192.168.1.1');
IPv6::isValid('2600::');
```

#### Access the parsed IP
```php
echo $ip; // print nicely formated IP with cidr/prefix

echo $ip->address; // print just the address
echo $ip->cidr; // print the prefix length

echo $ip->compressed(); // Compresses IP addresses for easy reading
echo $ip->uncompressed(); // Uncompresses IP addresses for easy parsing
```

#### Handle network operations:
```php
if ($ip->inNetwork('192.168.1.1/24')) {
    echo $ip->getNetwork();
}
```

#### Parse from Hex (useful for SNMP)
```php
$ip = IP::fromHexString('c0a801fe');
```

## License
Copyright (C) 2017-2018 Tony Murray

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/.

[LICENSE](LICENSE) contains a copy of the full GPLv3 licensing conditions.
