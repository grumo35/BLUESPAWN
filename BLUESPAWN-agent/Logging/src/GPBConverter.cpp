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
			if (detection->DetectionType == DetectionType::File) {

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
			if (detection->DetectionType == DetectionType::Registry) {

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
			// Extract all REGISTRY_DETECTION objects
			if (detection->DetectionType == DetectionType::Process) {

				// Convert REGISTRY_DETECTION struct to GPB object
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
		return std::vector<gpb::ServiceReactionData>();
	}

	void GPBConverter::CopyFileReaction(gpb::FileReactionData reactionData, gpb::FileReactionData* pFileReactionData) {

	}

	void GPBConverter::CopyRegistryReaction(gpb::RegistryReactionData reactionData, gpb::RegistryReactionData* pFileReactionData) {

	}

	void GPBConverter::CopyProcessReaction(gpb::ProcessReactionData reactionData, gpb::ProcessReactionData* pFileReactionData) {

	}

	void GPBConverter::CopyServiceReaction(gpb::ServiceReactionData reactionData, gpb::ServiceReactionData* pFileReactionData) {

	}

	gpb::HuntMessage GPBConverter::CreateHuntMessage(const std::string& message, const HuntInfo& info, const std::vector<DETECTION*>& detections) {
		gpb::HuntMessage huntMessage;
		huntMessage.set_allocated_info(&HuntInfoToGPB(info));
		huntMessage.set_extramessage(message);

		auto fileReactionList = GetFileReactions(detections);
		gpb::FileReactionData* pFileReaction;
		for (auto fileReaction : fileReactionList) {
			pFileReaction = huntMessage.add_filedetections();
			CopyFileReaction(fileReaction, pFileReaction);
		}

		return huntMessage;
	}

}