/*
 * network.cpp
 *
 * This source file is part of the FoundationDB open source project
 *
 * Copyright 2013-2018 Apple Inc. and the FoundationDB project authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "boost/asio.hpp"

#include "flow/network.h"
#include "flow/flow.h"
#include "flow/UnitTest.h"

IPAddress::IPAddress() : isV6addr(false) {
	addr.v4 = 0;
}

IPAddress::IPAddress(const boost::asio::ip::address& ipaddr) : isV6addr(ipaddr.is_v6()) {
	if (ipaddr.is_v6()) {
		addr.v6 = ipaddr.to_v6().to_bytes();
	} else {
		addr.v4 = ipaddr.to_v4().to_ulong();
	}
}

IPAddress::IPAddress(const IPAddressStore& v6addr) : isV6addr(true) {
	addr.v6 = v6addr;
}

IPAddress::IPAddress(uint32_t v4addr) : isV6addr(false) {
	addr.v4 = v4addr;
}

bool IPAddress::operator==(const IPAddress& rhs) const {
	return isV6addr == rhs.isV6addr && (isV6addr ? addr.v6 == rhs.addr.v6 : addr.v4 == rhs.addr.v4);
}

bool IPAddress::operator!=(const IPAddress& addr) const {
	return !(*this == addr);
}

bool IPAddress::operator<(const IPAddress& rhs) const {
	if(isV6addr != rhs.isV6addr) {
		return isV6addr < rhs.isV6addr;
	}
	if(isV6addr) {
		return addr.v6 < rhs.addr.v6;
	}
	return addr.v4 < rhs.addr.v4;
}

std::string IPAddress::toString() const {
	if (isV6addr) {
		return boost::asio::ip::address_v6(addr.v6).to_string();
	} else {
		return format("%d.%d.%d.%d", (addr.v4 >> 24) & 0xff, (addr.v4 >> 16) & 0xff, (addr.v4 >> 8) & 0xff, addr.v4 & 0xff);
	}
}

Optional<IPAddress> IPAddress::parse(std::string str) {
	try {
		auto addr = boost::asio::ip::address::from_string(str);
		return IPAddress(addr);
	} catch (...) {
		return Optional<IPAddress>();
	}
}

bool IPAddress::isValid() const {
	if (isV6addr) {
		return std::any_of(addr.v6.begin(), addr.v6.end(), [](uint8_t part) { return part != 0; });
	}
	return addr.v4 != 0;
}

static NetworkAddress parseNetworkAddress( std::string const& s, bool use_dns ) {
	if (s.empty()) {
		throw connection_string_invalid();
	}

	bool isTLS = false;
	std::string f;
	if( s.size() > 4 && strcmp(s.c_str() + s.size() - 4, ":tls") == 0 ) {
		isTLS = true;
		f = s.substr(0, s.size() - 4);
	} else {
		f = s;
	}

	std::string hostName, host, port;
	if (f[0] == '[') {
		// IPv6 address/port pair is represented as "[ip]:port"
		auto addrEnd = f.find_first_of(']');
		if (addrEnd == std::string::npos || f[addrEnd + 1] != ':')
			throw connection_string_invalid();

		hostName = f.substr(0, addrEnd+1);
		host = f.substr(1, addrEnd - 1);
		port = f.substr(addrEnd + 2);
	} else {
		auto addrEnd = f.find_last_of(':');
		if (addrEnd == std::string::npos)
			throw connection_string_invalid();

		hostName = f.substr(0, addrEnd);
		host = hostName;
		port = f.substr(addrEnd + 1, f.size());
	}

	try {
		boost::asio::io_service io_service;
		boost::asio::ip::tcp::resolver resolver(io_service);

		auto flags = boost::asio::ip::tcp::resolver::numeric_service;
		if (!use_dns) {
			flags = flags | boost::asio::ip::tcp::resolver::numeric_host;
		}

		boost::asio::ip::tcp::resolver::iterator ipaddrs = resolver.resolve(host, port, flags);
		return NetworkAddress(hostName, *ipaddrs, true, isTLS);
	} catch (...) {
		throw connection_string_invalid();
	}
}

NetworkAddress NetworkAddress::parse( std::string const& s ) {
	return parseNetworkAddress(s, true);
}

static std::vector<std::string> parseAddressList( std::string const& addrs ) {
	// Split addrs on ',' and parse them individually
	std::vector<std::string> lst;
	for(int p = 0; p <= addrs.size(); ) {
		int pComma = addrs.find_first_of(',', p);
		if (pComma == addrs.npos) pComma = addrs.size();
		lst.push_back(addrs.substr(p, pComma-p));
		p = pComma + 1;
	}
	return lst;
}

std::vector<NetworkAddress> NetworkAddress::parseList( std::string const& addrs ) {
	std::vector<std::string> addr_lst = parseAddressList(addrs);
	std::vector<NetworkAddress> coord(addr_lst.size());
	std::transform(addr_lst.begin(), addr_lst.end(), coord.begin(), parse);
	return coord;
}

std::string NetworkAddress::hostName() const {
	return host.empty() ? ip.toString() : host;
}

std::string NetworkAddress::toString() const {
	if (host.empty())
		return formatIpPort(ip, port) + (isTLS() ? ":tls" : "");
	else
		return formatHostPort(host, port) + (isTLS() ? ":tls" : "");
}

std::string toIPVectorString(std::vector<uint32_t> ips) {
	std::string output;
	const char* space = "";
	for (auto ip : ips) {
		output += format("%s%d.%d.%d.%d", space, (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
		space = " ";
	}
	return output;
}

std::string toIPVectorString(const std::vector<IPAddress>& ips) {
	std::string output;
	const char* space = "";
	for (auto ip : ips) {
		output += format("%s%s", space, ip.toString().c_str());
		space = " ";
	}
	return output;
}

std::string formatIpPort(const IPAddress& ip, uint16_t port) {
	const char* patt = ip.isV6() ? "[%s]:%d" : "%s:%d";
	return format(patt, ip.toString().c_str(), port);
}

std::string formatHostPort(const std::string& host, uint16_t port) {
	return format("%s:%d", host.c_str(), port);
}

Future<Reference<IConnection>> INetworkConnections::connect( std::string host, std::string service, bool useTLS ) {
	// Use map to create an actor that returns an endpoint or throws
	Future<NetworkAddress> pickEndpoint = map(resolveTCPEndpoint(host, service), [=](std::vector<NetworkAddress> const &addresses) -> NetworkAddress {
		NetworkAddress addr = addresses[g_random->randomInt(0, addresses.size())];
		if(useTLS)
			addr.flags = NetworkAddress::FLAG_TLS;
		return addr;
	});

	// Wait for the endpoint to return, then wait for connect(endpoint) and return it.
	// Template types are being provided explicitly because they can't be automatically deduced for some reason.
	return mapAsync<NetworkAddress, std::function<Future<Reference<IConnection>>(NetworkAddress const &)>, Reference<IConnection> >
		(pickEndpoint, [=](NetworkAddress const &addr) -> Future<Reference<IConnection>> {
		return connect(addr, host);
	});
}

TEST_CASE("/flow/network/ipaddress") {
	ASSERT(NetworkAddress::parse("[::1]:4800").toString() == "[::1]:4800");

	{
		auto addr = "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:4800";
		auto addrParsed = NetworkAddress::parse(addr);
		auto addrCompressed = "[2001:db8:85a3::8a2e:370:7334]:4800";
		ASSERT(addrParsed.isV6());
		ASSERT(!addrParsed.isTLS());
		ASSERT(addrParsed.toString() == addrCompressed);
	}

	{
		auto addr = "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:4800:tls";
		auto addrParsed = NetworkAddress::parse(addr);
		auto addrCompressed = "[2001:db8:85a3::8a2e:370:7334]:4800:tls";
		ASSERT(addrParsed.isV6());
		ASSERT(addrParsed.isTLS());
		ASSERT(addrParsed.toString() == addrCompressed);
	}

	{
		auto addr = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
		auto addrCompressed = "2001:db8:85a3::8a2e:370:7334";
		auto addrParsed = IPAddress::parse(addr);
		ASSERT(addrParsed.present());
		ASSERT(addrParsed.get().toString() == addrCompressed);
	}

	{
		auto addr = "2001";
		auto addrParsed = IPAddress::parse(addr);
		ASSERT(!addrParsed.present());
	}

	{
		auto addr = "8.8.8.8:12";
		auto addrParsed = IPAddress::parse(addr);
		ASSERT(!addrParsed.present());
	}

	return Void();
}
