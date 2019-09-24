#pragma once

#include "ReactionData.pb.h"
#include "iostream"
#include "reactions/Detections.h"

namespace Log {

	class GPBConverter {
	public:
		static std::string wstring_to_string(const std::wstring& str);

		static gpb::HuntMessage CreateHuntMessage(const std::string& message, const HuntInfo& info, const std::vector<DETECTION*>& detections);

		static gpb::Aggressiveness HuntAggressivenessToGPB(const Aggressiveness& info);
		static std::vector<gpb::Tactic> HuntTacticsToGPB(const DWORD& info);
		static std::vector<gpb::Category> HuntCategoriesToGPB(const DWORD& info);
		static std::vector<gpb::DataSource> HuntDatasourcesToGPB(const DWORD& info);
		static gpb::HuntInfo HuntInfoToGPB(const HuntInfo& info);

		static std::vector<gpb::FileReactionData> GetFileReactions(const std::vector<DETECTION*>& detections);
		static std::vector<gpb::RegistryReactionData> GetRegistryReactions(const std::vector<DETECTION*>& detections);
		static std::vector<gpb::ProcessReactionData> GetProcessReactions(const std::vector<DETECTION*>& detections);
		static std::vector<gpb::ServiceReactionData> GetServiceReactions(const std::vector<DETECTION*>& detections);

		static void CopyFileReaction(gpb::FileReactionData &reactionData, gpb::FileReactionData* pFileReactionData);
		static void CopyRegistryReaction(gpb::RegistryReactionData &reactionData, gpb::RegistryReactionData* pFileReactionData);
		static void CopyProcessReaction(gpb::ProcessReactionData &reactionData, gpb::ProcessReactionData* pFileReactionData);
		static void CopyServiceReaction(gpb::ServiceReactionData &reactionData, gpb::ServiceReactionData* pFileReactionData);
	};
}