/**
 * Copyright 2020 SkillTree
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
package skills.controller.result.model

import groovy.transform.Canonical
import skills.services.userActions.DashboardAction
import skills.services.userActions.DashboardItem

@Canonical
class DashboardUserActionRes {
    Long id
    DashboardAction action
    DashboardItem item
    String itemId
    Integer itemRefId

    String userId
    String userIdForDisplay
    String projectId
    String quizId

    Date created
}