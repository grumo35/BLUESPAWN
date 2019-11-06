#include <Windows.h>

#include <iostream>
#include "logging/GPBConverter.h"
#include "logging/ServerSink.h"

using grpc::Channel;
using grpc::Status;
using gpb::BLUESPAWN;

namespace Log {

	void ServerSink::LogMessage(const LogLevel& level, const std::string& message, const HuntInfo& info, 
		const std::vector<std::shared_ptr<DETECTION>>& detections){
		if (!level.Enabled())
			return;

		gpb::HuntMessage gpbMessage = GPBConverter::CreateHuntMessage(message, info, detections);
		gpb::Empty reply;
		grpc::ClientContext context;

		if(level.severity == Severity::LogHunt){

			std::cout << "SENDING MESSAGE . . . . " << std::endl;
			grpc::Status status = stub_->SendHuntMessage(&context, gpbMessage, &reply);
			std::cout << "MESAGE SENT" << std::endl;

			if (!status.ok()) 
				std::cout << status.error_code() << ": " << status.error_message() << std::endl;
		}

	}

	bool ServerSink::operator==(const LogSink& sink) const {
		return (bool) dynamic_cast<const ServerSink*>(&sink);
	}
}