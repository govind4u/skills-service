/**
 * Copyright 2024 SkillTree
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
package skills.dbupgrade.s3

import org.springframework.context.annotation.Condition
import org.springframework.context.annotation.ConditionContext
import org.springframework.core.env.ConfigurableEnvironment
import org.springframework.core.type.AnnotatedTypeMetadata

class UpgradeInProgressWithS3Condition implements Condition {

    @Override
    boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        ConfigurableEnvironment environment = context.getEnvironment();
        String eventPath = environment.getProperty("skills.queued-event-path");
        String upgradeInProgress = environment.getProperty("skills.config.db-upgrade-in-progress");
        return eventPath?.startsWith("s3:/") && upgradeInProgress?.toLowerCase()?.equals("true")
    }
}