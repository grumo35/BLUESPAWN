#include <Windows.h>

#include <iostream>

#include "logging/ServerSink.h"

namespace Log {

	void ServerSink::LogMessage(const LogLevel& level, const std::string& message, const HuntInfo& info, const std::vector<DETECTION*>& detections){
		if (!level.Enabled())
			return;

		gpb::HuntMessage message = GPBConverter::CreateHuntMessage(message, info, detections);

		if(level.severity == Severity::LogHunt){
			
		} else {
			
		}
	}

	bool ServerSink::operator==(const LogSink& sink) const {
		return (bool) dynamic_cast<const ServerSink*>(&sink);
	}
}