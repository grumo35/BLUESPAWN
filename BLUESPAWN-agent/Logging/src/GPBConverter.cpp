#include "logging/GPBConverter.h"

namespace Log {

	std::string GPBConverter::wstring_to_string(const std::wstring& ws) {
		std::string s(ws.begin(), ws.end());
		return s;
	}

	gpb::Aggressiveness GPBConverter::HuntAggressivenessToGPB(const Aggressiveness& info) {
		return gpb::Aggressiveness();
	}

	std::vector<gpb::Tactic> GPBConverter::HuntTacticsToGPB(const DWORD& info) {
		return std::vector<gpb::Tactic>();
	}

	std::vector<gpb::Category> GPBConverter::HuntCategoriesToGPB(const DWORD& info) {
		return std::vector<gpb::Category>();
	}

	std::vector<gpb::DataSource> GPBConverter::HuntDatasourcesToGPB(const DWORD& info) {
		return std::vector<gpb::DataSource>();
	}

	gpb::HuntInfo GPBConverter::HuntInfoToGPB(const HuntInfo& info) {
		gpb::HuntInfo gpbInfo;

		gpbInfo.set_huntname(wstring_to_string(info.HuntName));
		gpbInfo.set_huntaggressiveness(HuntAggressivenessToGPB(info.HuntAggressiveness));

		auto huntTactics = HuntTacticsToGPB(info.HuntTactics);
		for (int i = 0; i < huntTactics.size(); i++)
			gpbInfo.set_hunttactics(i, huntTactics[i]);

		auto huntCategories = HuntCategoriesToGPB(info.HuntCategories);
		for (int i = 0; i < huntCategories.size(); i++)
			gpbInfo.set_huntcategories(i, huntCategories[i]);

		auto huntDatasources = HuntDatasourcesToGPB(info.HuntDatasources);
		for (int i = 0; i < huntDatasources.size(); i++)
			gpbInfo.set_huntdatasources(i, huntDatasources[i]);

		gpbInfo.set_huntstarttime(info.HuntStartTime);

		return gpbInfo;
	}

	std::vector<gpb::FileReactionData> GPBConverter::GetFileReactions(const std::vector<DETECTION*>& detections) {
		std::vector<gpb::FileReactionData> fileDetections;

		for (auto& detection : detections) {
			// Extract all FILE_DETECTION objects
			if (detection->Type == DetectionType::File) {

				// Convert FILE_DETECTION struct to GPB object
				FILE_DETECTION* pFileDetection = (FILE_DETECTION*)detection;

				gpb::FileReactionData gpbFileDetection;
				gpbFileDetection.set_filename(wstring_to_string(pFileDetection->wsFileName));
				gpbFileDetection.set_hash((char*)(pFileDetection->hash));

				fileDetections.emplace_back(gpbFileDetection);
			}
		}

		return fileDetections;
	}

	std::vector<gpb::RegistryReactionData> GPBConverter::GetRegistryReactions(const std::vector<DETECTION*>& detections) {
		std::vector<gpb::RegistryReactionData> regDetections;

		for (auto& detection : detections) {
			// Extract all REGISTRY_DETECTION objects
			if (detection->Type == DetectionType::Registry) {

				// Convert REGISTRY_DETECTION struct to GPB object
				REGISTRY_DETECTION* pRegDetection = (REGISTRY_DETECTION*)detection;

				gpb::RegistryReactionData gpbRegDetection;
				gpbRegDetection.set_path(wstring_to_string(pRegDetection->wsRegistryKeyPath));
				gpbRegDetection.set_value(wstring_to_string(pRegDetection->wsRegistryKeyValue));
				gpbRegDetection.set_contents((char*)(pRegDetection->contents));

				regDetections.emplace_back(gpbRegDetection);
			}
		}

		return regDetections;
	}

	std::vector<gpb::ProcessReactionData> GPBConverter::GetProcessReactions(const std::vector<DETECTION*>& detections) {
		std::vector<gpb::ProcessReactionData> procDetections;

		for (auto& detection : detections) {
			// Extract all PROCESS_DETECTION objects
			if (detection->Type == DetectionType::Process) {

				// Convert PROCESS_DETECTION struct to GPB object
				PROCESS_DETECTION* pProcDetection = (PROCESS_DETECTION*)detection;

				gpb::ProcessReactionData gpbProcDetection;
				gpbProcDetection.set_name(wstring_to_string(pProcDetection->wsImageName));
				gpbProcDetection.set_path(wstring_to_string(pProcDetection->wsImagePath));
				gpbProcDetection.set_commandline(wstring_to_string(pProcDetection->wsCmdline));
				gpbProcDetection.set_pid(pProcDetection->PID);
				gpbProcDetection.set_tid(pProcDetection->TID);

				gpb::ProcessReactionData_ProcessDetectionMethod method;
				switch (pProcDetection->method) {
				case ProcessDetectionMethod::NotImageBacked:
					method = gpb::ProcessReactionData_ProcessDetectionMethod_NotImageBacked;
					break;
				case ProcessDetectionMethod::BackingImageMismatch:
					method = gpb::ProcessReactionData_ProcessDetectionMethod_BackingImageMismatch;
					break;
				case ProcessDetectionMethod::NotInLoader:
					method = gpb::ProcessReactionData_ProcessDetectionMethod_NotInLoader;
					break;
				case ProcessDetectionMethod::NotSigned:
					method = gpb::ProcessReactionData_ProcessDetectionMethod_NotSigned;
					break;
				}
				gpbProcDetection.set_detectionmethod(method);

				gpbProcDetection.set_allocationstart((char*)(pProcDetection->AllocationStart));

				procDetections.emplace_back(gpbProcDetection);
			}
		}

		return procDetections;
	}

	std::vector<gpb::ServiceReactionData> GPBConverter::GetServiceReactions(const std::vector<DETECTION*>& detections) {
		std::vector<gpb::ServiceReactionData> serviceDetections;

		for (auto& detection : detections) {
			// Extract all SERVICE_DETECTION objects
			if (detection->Type == DetectionType::Service) {

				// Convert SERVICE_DETECTION struct to GPB object
				SERVICE_DETECTION* pServiceDetection = (SERVICE_DETECTION*)detection;

				gpb::ServiceReactionData gpbServiceDetection;
				gpbServiceDetection.set_name(wstring_to_string(pServiceDetection->wsServiceName));
				gpbServiceDetection.set_binarypath(wstring_to_string(pServiceDetection->wsServiceExecutablePath));
				gpbServiceDetection.set_servicedll(wstring_to_string(pServiceDetection->wsServiceDll));
				gpbServiceDetection.set_pid(pServiceDetection->ServicePID);

				serviceDetections.emplace_back(gpbServiceDetection);
			}
		}

		return serviceDetections;
	}

	void GPBConverter::CopyFileReaction(gpb::FileReactionData &reactionData, gpb::FileReactionData* pFileReactionData) {
		pFileReactionData->set_filename(reactionData.filename());
		pFileReactionData->set_hash(reactionData.hash());
	}

	void GPBConverter::CopyRegistryReaction(gpb::RegistryReactionData &reactionData, gpb::RegistryReactionData* pRegReactionData) {
		pRegReactionData->set_path(reactionData.path());
		pRegReactionData->set_value(reactionData.value());
		pRegReactionData->set_contents(reactionData.contents());
	}

	void GPBConverter::CopyProcessReaction(gpb::ProcessReactionData &reactionData, gpb::ProcessReactionData* pProcessReactionData) {
		pProcessReactionData->set_name(reactionData.name());
		pProcessReactionData->set_path(reactionData.path());
		pProcessReactionData->set_commandline(reactionData.commandline());
		pProcessReactionData->set_pid(reactionData.pid());
		pProcessReactionData->set_tid(reactionData.tid());
		pProcessReactionData->set_detectionmethod(reactionData.detectionmethod());
		pProcessReactionData->set_allocationstart(reactionData.allocationstart());
	}

	void GPBConverter::CopyServiceReaction(gpb::ServiceReactionData &reactionData, gpb::ServiceReactionData* pServiceReactionData) {
		pServiceReactionData->set_name(reactionData.name());
		pServiceReactionData->set_binarypath(reactionData.binarypath());
		pServiceReactionData->set_servicedll(reactionData.servicedll());
		pServiceReactionData->set_pid(reactionData.pid());
	}

	gpb::HuntMessage GPBConverter::CreateHuntMessage(const std::string& message, const HuntInfo& info, const std::vector<DETECTION*>& detections) {
		gpb::HuntMessage huntMessage;
		huntMessage.set_allocated_info(&HuntInfoToGPB(info));
		huntMessage.set_extramessage(message);

		// Add FileReactionData objects
		auto fileReactionList = GetFileReactions(detections);
		gpb::FileReactionData* pFileReaction;
		for (auto fileReaction : fileReactionList) {
			pFileReaction = huntMessage.add_filedetections();
			CopyFileReaction(fileReaction, pFileReaction);
		}

		// Add RegistryReactionData objects
		auto regReactionList = GetRegistryReactions(detections);
		gpb::RegistryReactionData* pRegReaction;
		for (auto regReaction : regReactionList) {
			pRegReaction = huntMessage.add_registrydetections();
			CopyRegistryReaction(regReaction, pRegReaction);
		}

		// Add ProcessReactionData objects
		auto regProcessList = GetProcessReactions(detections);
		gpb::ProcessReactionData* pProcReaction;
		for (auto procReaction : regProcessList) {
			pProcReaction = huntMessage.add_processdetections();
			CopyProcessReaction(procReaction, pProcReaction);
		}

		// Add ServiceReactionData objects
		auto serviceProcessList = GetServiceReactions(detections);
		gpb::ServiceReactionData* pServReaction;
		for (auto servReaction : serviceProcessList) {
			pServReaction = huntMessage.add_servicedetections();
			CopyServiceReaction(servReaction, pServReaction);
		}

		return huntMessage;
	}

}