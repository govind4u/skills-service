/**
 * Copyright 2021 SkillTree
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package skills.metrics.builders.skill


import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Component
import skills.controller.exceptions.ErrorCode
import skills.controller.exceptions.SkillException
import skills.metrics.builders.MetricsParams
import skills.metrics.builders.ProjectMetricsBuilder
import skills.storage.model.SkillDef
import skills.storage.model.UserEvent
import skills.storage.model.UserMetrics
import skills.storage.repos.SkillDefRepo
import skills.storage.repos.UserAchievedLevelRepo
import skills.storage.repos.UserEventsRepo

@Component
class UsagePostAchievementUsersBuilder implements ProjectMetricsBuilder{

    @Autowired
    UserEventsRepo userEventsRepo

    @Autowired
    SkillDefRepo skillDefRepo

    @Autowired
    UserAchievedLevelRepo userAchievedLevelRepo

    @Override
    String getId() {
        return "usagePostAchievementUsersBuilder"
    }

    @Override
    Object build(String projectId, String chartId, Map<String, String> props) {
        String skillId = MetricsParams.getSkillId(projectId, chartId, props)
        SkillDef skillDef = skillDefRepo.findByProjectIdAndSkillId(projectId, skillId)
        if (!skillDef) {
            throw new SkillException("Skill does not exist", projectId, skillId, ErrorCode.SkillNotFound)
        }
        List<UserMetrics> usersPostAchievement = userEventsRepo.getUsersUsingSkillAfterAchievement(skillDef.id, 1) ?: null

        return usersPostAchievement
    }
}
