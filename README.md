# ip-utils

A set of utility classes for working with IP addresses. Its most important features:

## A lightweight IP address implementation

An [IP address implementation](https://robtimus.github.io/ip-utils/apidocs/com/github/robtimus/net/ip/IPAddress.html) that has the following advantages over [InetAddress](https://docs.oracle.com/javase/8/docs/api/java/net/InetAddress.html):

* It's very lightweight; for instance, it does not provide any functionality for hostname lookups or other functionality that requires network access.
* Its factory methods support the more generic [CharSequence](https://docs.oracle.com/javase/8/docs/api/java/lang/CharSequence.html) instead of only [String](https://docs.oracle.com/javase/8/docs/api/java/lang/String.html).
* Its factory methods do not throw checked exceptions (like [UnknownHostException](https://docs.oracle.com/javase/8/docs/api/java/net/UnknownHostException.html)).
* It supports native parsing to [Optional](https://docs.oracle.com/javase/8/docs/api/java/util/Optional.html) without having to catch any exceptions.
* It supports native parsing to `byte[]`.
* It supports native parsing with [ParsePosition](https://docs.oracle.com/javase/8/docs/api/java/text/ParsePosition.html).
* It is [Comparable](https://docs.oracle.com/javase/8/docs/api/java/lang/Comparable.html).

To interact with existing code, it comes with bridge methods to convert to and from [InetAddress](https://docs.oracle.com/javase/8/docs/api/java/net/InetAddress.html). This allows you to replace most occurrences of [InetAddress](https://docs.oracle.com/javase/8/docs/api/java/net/InetAddress.html), [Inet4Address](https://docs.oracle.com/javase/8/docs/api/java/net/Inet4Address.html) and [Inet6Address](https://docs.oracle.com/javase/8/docs/api/java/net/Inet6Address.html) with [IPAddress](https://robtimus.github.io/ip-utils/apidocs/com/github/robtimus/net/ip/IPAddress.html), [IPv4Address](https://robtimus.github.io/ip-utils/apidocs/com/github/robtimus/net/ip/IPv4Address.html) and [IPv6Address](https://robtimus.github.io/ip-utils/apidocs/com/github/robtimus/net/ip/IPv6Address.html) respectively.

## Efficient IP range and subnet implementations

This library makes it possible to create an IP range from two IP addresses, or a subnet from a CIDR notation or an IP address and prefix length. This IP range or subnet is an immutable [Collection](https://docs.oracle.com/javase/8/docs/api/java/util/Collection.html) of IP addresses with possibly thousands of elements, without the need to store all of these IP addresses.

## Bean Validation support

The [ip-validation](https://robtimus.github.io/ip-validation/) library uses this library to provide validation constraints that work on both [CharSequence](https://docs.oracle.com/javase/8/docs/api/java/lang/CharSequence.html) and [IPAddress](https://robtimus.github.io/ip-utils/apidocs/com/github/robtimus/net/ip/IPAddress.html). These not only allow you to validate that a value is a valid IP address, but also that the IP address is contained in a specific IP range or subnet.
