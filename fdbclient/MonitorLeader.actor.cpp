/*
 * MonitorLeader.actor.cpp
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

#include "fdbclient/MonitorLeader.h"
#include "fdbclient/CoordinationInterface.h"
#include "flow/ActorCollection.h"
#include "flow/UnitTest.h"
#include "fdbrpc/genericactors.actor.h"
#include "fdbrpc/Platform.h"
#include "flow/actorcompiler.h" // has to be last include

std::pair< std::string, bool > ClusterConnectionFile::lookupClusterFileName( std::string const& filename ) {
	if (filename.length())
		return std::make_pair(filename, false);

	std::string f;
	bool isDefaultFile = true;
	if (platform::getEnvironmentVar(CLUSTER_FILE_ENV_VAR_NAME, f)) {
		// If this is set but points to a file that does not
		// exist, we will not fallback to any other methods
		isDefaultFile = false;
	} else if (fileExists("fdb.cluster"))
		f = "fdb.cluster";
	else
		f = platform::getDefaultClusterFilePath();

	return std::make_pair( f, isDefaultFile );
}

std::string ClusterConnectionFile::getErrorString( std::pair<std::string, bool> const& resolvedClusterFile, Error const& e ) {
	bool isDefault = resolvedClusterFile.second;
	if( e.code() == error_code_connection_string_invalid ) {
		return format("Invalid cluster file `%s': %d %s", resolvedClusterFile.first.c_str(), e.code(), e.what());
	} else if( e.code() == error_code_no_cluster_file_found ) {
		if( isDefault )
			return format("Unable to read cluster file `./fdb.cluster' or `%s' and %s unset: %d %s",
						  platform::getDefaultClusterFilePath().c_str(), CLUSTER_FILE_ENV_VAR_NAME, e.code(), e.what());
		else
			return format("Unable to read cluster file `%s': %d %s", resolvedClusterFile.first.c_str(), e.code(), e.what());
	} else {
		return format("Unexpected error loading cluster file `%s': %d %s", resolvedClusterFile.first.c_str(), e.code(), e.what());
	}
}

ClusterConnectionFile::ClusterConnectionFile( std::string const& filename ) {
	if( !fileExists( filename ) ) {
		throw no_cluster_file_found();
	}

	cs = ClusterConnectionString(readFileBytes(filename, MAX_CLUSTER_FILE_BYTES));
	this->filename = filename;
	setConn = false;
}

ClusterConnectionFile::ClusterConnectionFile(std::string const& filename, ClusterConnectionString const& contents) {
	this->filename = filename;
	cs = contents;
	setConn = true;
}

ClusterConnectionString const& ClusterConnectionFile::getConnectionString() const {
	return cs;
}

void ClusterConnectionFile::notifyConnected() {
	if (setConn){
		this->writeFile();
	}
}

bool ClusterConnectionFile::fileContentsUpToDate() const {
	ClusterConnectionString temp;
	return fileContentsUpToDate(temp);
}

bool ClusterConnectionFile::fileContentsUpToDate(ClusterConnectionString &fileConnectionString) const {
	try {
		// the cluster file hasn't been created yet so there's nothing to check
		if (setConn)
			return true;

		ClusterConnectionFile temp( filename );
		fileConnectionString = temp.getConnectionString();
		return fileConnectionString.toString() == cs.toString();
	}
	catch (Error& e) {
		TraceEvent(SevWarnAlways, "ClusterFileError").error(e).detail("Filename", filename);
		return false; // Swallow the error and report that the file is out of date
	}
}

bool ClusterConnectionFile::writeFile() {
	setConn = false;
	if(filename.size()) {
		try {
			atomicReplace( filename, "# DO NOT EDIT!\n# This file is auto-generated, it is not to be edited by hand\n" + cs.toString().append("\n") );
			if(!fileContentsUpToDate()) {
				// This should only happen in rare scenarios where multiple processes are updating the same file to different values simultaneously
				// In that case, we don't have any guarantees about which file will ultimately be written
				TraceEvent(SevWarnAlways, "ClusterFileChangedAfterReplace").detail("Filename", filename).detail("ConnStr", cs.toString());
				return false;
			}

			return true;
		} catch( Error &e ) {
			TraceEvent(SevWarnAlways, "UnableToChangeConnectionFile").error(e).detail("Filename", filename).detail("ConnStr", cs.toString());
		}
	}

	return false;
}

void ClusterConnectionFile::setConnectionString( ClusterConnectionString const& conn ) {
	ASSERT( filename.size() );
	cs = conn;
	writeFile();
}

std::string ClusterConnectionString::getErrorString( std::string const& source, Error const& e ) {
	if( e.code() == error_code_connection_string_invalid ) {
		return format("Invalid connection string `%s: %d %s", source.c_str(), e.code(), e.what());
	}
	else {
		return format("Unexpected error parsing connection string `%s: %d %s", source.c_str(), e.code(), e.what());
	}
}

std::string trim( std::string const& connectionString ) {
	// Strip out whitespace
	// Strip out characters between a # and a newline
	std::string trimmed;
	auto end = connectionString.end();
	for(auto c=connectionString.begin(); c!=end; ++c) {
		if (*c == '#') {
			++c;
			while(c!=end && *c != '\n' && *c != '\r')
				++c;
			if(c == end)
				break;
		}
		else if (*c != ' ' && *c != '\n' && *c != '\r' && *c != '\t')
			trimmed += *c;
	}
	return trimmed;
}

ClusterConnectionString::ClusterConnectionString( std::string const& connectionString ) {
	auto trimmed = trim(connectionString);

	// Split on '@' into key@addrs
	int pAt = trimmed.find_first_of('@');
	if (pAt == trimmed.npos)
		throw connection_string_invalid();
	std::string key = trimmed.substr(0, pAt);
	std::string addrs = trimmed.substr(pAt+1);

	parseKey(key);

	coord = NetworkAddress::parseList(addrs);
	ASSERT( coord.size() > 0 );  // parseList() always returns at least one address if it doesn't throw

	std::sort( coord.begin(), coord.end() );
	// Check that there are no duplicate addresses
	if ( std::unique( coord.begin(), coord.end() ) != coord.end() )
		throw connection_string_invalid();
}

TEST_CASE("/fdbclient/MonitorLeader/parseConnectionString/basic") {
	std::string input;

	{
		input = "asdf:2345@1.1.1.1:345";
		ClusterConnectionString cs(input);
		ASSERT( input == cs.toString() );
	}

	{
		input = "0xxdeadbeef:100100100@1.1.1.1:34534,5.1.5.3:23443";
		ClusterConnectionString cs(input);
		ASSERT( input == cs.toString() );
	}

	{
		input = "0xxdeadbeef:100100100@1.1.1.1:34534,5.1.5.3:23443";
		std::string commented("#start of comment\n");
		commented += input;
		commented += "\n";
		commented += "# asdfasdf ##";

		ClusterConnectionString cs(commented);
		ASSERT( input == cs.toString() );
	}

	{
		input = "0xxdeadbeef:100100100@[::1]:1234,[::1]:1235";
		std::string commented("#start of comment\n");
		commented += input;
		commented += "\n";
		commented += "# asdfasdf ##";

		ClusterConnectionString cs(commented);
		ASSERT(input == cs.toString());
	}

	{
		input = "0xxdeadbeef:100100100@[abcd:dcba::1]:1234,[abcd:dcba::abcd:1]:1234";
		std::string commented("#start of comment\n");
		commented += input;
		commented += "\n";
		commented += "# asdfasdf ##";

		ClusterConnectionString cs(commented);
		ASSERT(input == cs.toString());
	}

	return Void();
}

TEST_CASE("/fdbclient/MonitorLeader/parseConnectionString/fuzz") {
	// For a static connection string, add in fuzzed comments and whitespace
	// SOMEDAY: create a series of random connection strings, rather than the one we started with
	std::string connectionString = "0xxdeadbeef:100100100@1.1.1.1:34534,5.1.5.3:23443";
	for(int i=0; i<10000; i++)
	{
		std::string output("");
		auto c=connectionString.begin();
		while(c!=connectionString.end()) {
			if(g_random->random01() < 0.1) // Add whitespace character
				output += g_random->randomChoice(LiteralStringRef(" \t\n\r"));
			if(g_random->random01() < 0.5) { // Add one of the input characters
				output += *c;
				++c;
			}
			if(g_random->random01() < 0.1) { // Add a comment block
				output += "#";
				int charCount = g_random->randomInt(0, 20);
				for(int i = 0; i < charCount; i++) {
					output += g_random->randomChoice(LiteralStringRef("asdfzxcv123345:!@#$#$&()<\"\' \t"));
				}
				output += g_random->randomChoice(LiteralStringRef("\n\r"));
			}
		}

		ClusterConnectionString cs(output);
		ASSERT( connectionString == cs.toString() );
	}
	return Void();
}

ClusterConnectionString::ClusterConnectionString( vector<NetworkAddress> servers, Key key )
	: coord(servers)
{
	parseKey(key.toString());
}

void ClusterConnectionString::parseKey( std::string const& key ) {
	// Check the structure of the given key, and fill in this->key and this->keyDesc

	// The key must contain one (and only one) : character
	int colon = key.find_first_of(':');
	if (colon == key.npos)
		throw connection_string_invalid();
	std::string desc = key.substr(0, colon);
	std::string id = key.substr(colon+1);

	// Check that description contains only allowed characters (a-z, A-Z, 0-9, _)
	for(auto c=desc.begin(); c!=desc.end(); ++c)
		if (!(isalnum(*c) || *c == '_'))
			throw connection_string_invalid();

	// Check that ID contains only allowed characters (a-z, A-Z, 0-9)
	for(auto c=id.begin(); c!=id.end(); ++c)
		if (!isalnum(*c))
			throw connection_string_invalid();

	this->key = StringRef(key);
	this->keyDesc = StringRef(desc);
}

std::string ClusterConnectionString::toString() const {
	std::string s = key.toString();
	s += '@';
	for(int i=0; i<coord.size(); i++) {
		if (i) s += ',';
		s += coord[i].toString();
	}
	return s;
}

ClientCoordinators::ClientCoordinators( Reference<ClusterConnectionFile> ccf )
	: ccf(ccf)
{
	ClusterConnectionString cs = ccf->getConnectionString();
	for(auto s = cs.coordinators().begin(); s != cs.coordinators().end(); ++s)
		clientLeaderServers.push_back( ClientLeaderRegInterface( *s ) );
	clusterKey = cs.clusterKey();
}

UID WLTOKEN_CLIENTLEADERREG_GETLEADER( -1, 2 );

ClientLeaderRegInterface::ClientLeaderRegInterface( NetworkAddress remote )
	: getLeader( Endpoint({remote}, WLTOKEN_CLIENTLEADERREG_GETLEADER) )
{
}

ClientLeaderRegInterface::ClientLeaderRegInterface( INetwork* local ) {
	getLeader.makeWellKnownEndpoint( WLTOKEN_CLIENTLEADERREG_GETLEADER, TaskCoordination );
}

// Nominee is the worker among all workers that are considered as leader by a coordinator
// This function contacts a coordinator coord to ask if the worker is considered as a leader (i.e., if the worker
// is a nominee)
ACTOR Future<Void> monitorNominee( Key key, ClientLeaderRegInterface coord, AsyncTrigger* nomineeChange, Optional<LeaderInfo> *info, int generation, Reference<AsyncVar<int>> connectedCoordinatorsNum ) {
	state bool hasCounted = false;
	loop {
		state Optional<LeaderInfo> li = wait( retryBrokenPromise( coord.getLeader, GetLeaderRequest( key, info->present() ? info->get().changeID : UID() ), TaskCoordinationReply ) );
		if (li.present() && !hasCounted && connectedCoordinatorsNum.isValid()) {
			connectedCoordinatorsNum->set(connectedCoordinatorsNum->get() + 1);
			hasCounted = true;
		}
		wait( Future<Void>(Void()) ); // Make sure we weren't cancelled

		TraceEvent("GetLeaderReply").suppressFor(1.0).detail("Coordinator", coord.getLeader.getEndpoint().getPrimaryAddress()).detail("Nominee", li.present() ? li.get().changeID : UID()).detail("Generation", generation);

		if (li != *info) {
			*info = li;
			nomineeChange->trigger();

			if( li.present() && li.get().forward )
				wait( Future<Void>(Never()) );
			wait( Future<Void>(Void()) );
		}
	}
}

// Also used in fdbserver/LeaderElection.actor.cpp!
// bool represents if the LeaderInfo is a majority answer or not.
// This function also masks the first 7 bits of changeId of the nominees and returns the Leader with masked changeId
Optional<std::pair<LeaderInfo, bool>> getLeader( const vector<Optional<LeaderInfo>>& nominees ) {
	vector<LeaderInfo> maskedNominees;
	maskedNominees.reserve(nominees.size());
	for (auto &nominee : nominees) {
		if (nominee.present()) {
			maskedNominees.push_back(nominee.get());
			maskedNominees.back().changeID = UID(maskedNominees.back().changeID.first() & LeaderInfo::mask, maskedNominees.back().changeID.second());
		}
	}

	// If any coordinator says that the quorum is forwarded, then it is
	for(int i=0; i<maskedNominees.size(); i++)
		if (maskedNominees[i].forward)
			return std::pair<LeaderInfo, bool>(maskedNominees[i], true);

	if(!maskedNominees.size())
		return Optional<std::pair<LeaderInfo, bool>>();

	std::sort(maskedNominees.begin(), maskedNominees.end(),
		[](const LeaderInfo& l, const LeaderInfo& r) { return l.changeID < r.changeID; });

	int bestCount = 0;
	LeaderInfo bestNominee;
	LeaderInfo currentNominee;
	int curCount = 0;
	for (int i = 0; i < maskedNominees.size(); i++) {
		if (currentNominee == maskedNominees[i]) {
			curCount++;
		}
		else {
			if (curCount > bestCount) {
				bestNominee = currentNominee;
				bestCount = curCount;
			}
			currentNominee = maskedNominees[i];
			curCount = 1;
		}
	}
	if (curCount > bestCount) {
		bestNominee = currentNominee;
		bestCount = curCount;
	}

	bool majority = bestCount >= nominees.size() / 2 + 1;
	return std::pair<LeaderInfo, bool>(bestNominee, majority);
}

struct MonitorLeaderInfo {
	bool hasConnected;
	Reference<ClusterConnectionFile> intermediateConnFile;
	int generation;

	MonitorLeaderInfo() : hasConnected(false), generation(0) {}
	explicit MonitorLeaderInfo( Reference<ClusterConnectionFile> intermediateConnFile ) : intermediateConnFile(intermediateConnFile), hasConnected(false), generation(0) {}
};

// Leader is the process that will be elected by coordinators as the cluster controller
ACTOR Future<MonitorLeaderInfo> monitorLeaderOneGeneration( Reference<ClusterConnectionFile> connFile, Reference<AsyncVar<Value>> outSerializedLeaderInfo, MonitorLeaderInfo info,  Reference<AsyncVar<int>> connectedCoordinatorsNum) {
	state ClientCoordinators coordinators( info.intermediateConnFile );
	state AsyncTrigger nomineeChange;
	state std::vector<Optional<LeaderInfo>> nominees;
	state Future<Void> allActors;

	nominees.resize(coordinators.clientLeaderServers.size());

	std::vector<Future<Void>> actors;
	// Ask all coordinators if the worker is considered as a leader (leader nominee) by the coordinator.
	for(int i=0; i<coordinators.clientLeaderServers.size(); i++)
		actors.push_back( monitorNominee( coordinators.clusterKey, coordinators.clientLeaderServers[i], &nomineeChange, &nominees[i], info.generation, connectedCoordinatorsNum) );
	allActors = waitForAll(actors);

	loop {
		Optional<std::pair<LeaderInfo, bool>> leader = getLeader(nominees);
		TraceEvent("MonitorLeaderChange").detail("NewLeader", leader.present() ? leader.get().first.changeID : UID(1,1));
		if (leader.present()) {
			if( leader.get().first.forward ) {
				TraceEvent("MonitorLeaderForwarding").detail("NewConnStr", leader.get().first.serializedInfo.toString()).detail("OldConnStr", info.intermediateConnFile->getConnectionString().toString());
				info.intermediateConnFile = Reference<ClusterConnectionFile>(new ClusterConnectionFile(connFile->getFilename(), ClusterConnectionString(leader.get().first.serializedInfo.toString())));
				return info;
			}
			if(connFile != info.intermediateConnFile) {
				if(!info.hasConnected) {
					TraceEvent(SevWarnAlways, "IncorrectClusterFileContentsAtConnection").detail("Filename", connFile->getFilename())
						.detail("ConnectionStringFromFile", connFile->getConnectionString().toString())
						.detail("CurrentConnectionString", info.intermediateConnFile->getConnectionString().toString());
				}
				connFile->setConnectionString(info.intermediateConnFile->getConnectionString());
				info.intermediateConnFile = connFile;
			}

			info.hasConnected = true;
			connFile->notifyConnected();

			outSerializedLeaderInfo->set( leader.get().first.serializedInfo );
		}
		wait( nomineeChange.onTrigger() || allActors );
	}
}

ACTOR Future<Void> monitorLeaderInternal( Reference<ClusterConnectionFile> connFile, Reference<AsyncVar<Value>> outSerializedLeaderInfo, Reference<AsyncVar<int>> connectedCoordinatorsNum ) {
	state MonitorLeaderInfo info(connFile);
	loop {
		// set the AsyncVar to 0
		if (connectedCoordinatorsNum.isValid()) connectedCoordinatorsNum->set(0);
		MonitorLeaderInfo _info = wait( monitorLeaderOneGeneration( connFile, outSerializedLeaderInfo, info, connectedCoordinatorsNum) );
		info = _info;
		info.generation++;

	}
}
