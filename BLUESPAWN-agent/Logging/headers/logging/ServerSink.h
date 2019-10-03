#pragma once

#include <map>

#include "LogSink.h"
#include "LogLevel.h"
#include "logging/GPBConverter.h"
#include "reactions/Detections.h"
#include "ReactionData.pb.h"
#include "ServerServices.grpc.pb.h"
#include <grpcpp/grpcpp.h>

using gpb::BLUESPAWN;

namespace Log {

	/**
	 * ServerSink provides a sink for the logger that directs output to a GPB server.
	 * 
	 */
	class ServerSink : public LogSink {
	private:
		std::string MessagePrepends[4] = { "[ERROR]", "[WARNING]", "[INFO]", "[OTHER]" };
		std::unique_ptr<BLUESPAWN::Stub> stub_;

	public:

		ServerSink(std::string ip, std::string port) :
			stub_(BLUESPAWN::NewStub(grpc::CreateChannel(ip + ":" + port, grpc::InsecureChannelCredentials()))) {}

		/**
		 * Outputs a message to the console if its logging level is enabled. The log message
		 * is prepended with its severity level.
		 *
		 * @param level The level at which the message is being logged
		 * @param message The message to log
		 */
		virtual void LogMessage(const LogLevel& level, const std::string& message, const HuntInfo& info = {}, const std::vector<DETECTION*>& detections = {});

		/**
		 * Compares this ServerSink to another LogSink. Currently, as only one console is supported,
		 * any other ServerSink is considered to be equal. This is subject to change in the event that
		 * support for more consoles is added.
		 *
		 * @param sink The LogSink to compare
		 *
		 * @return Whether or not the argument and this sink are considered equal.
		 */
		virtual bool operator==(const LogSink& sink) const;
	};
}
