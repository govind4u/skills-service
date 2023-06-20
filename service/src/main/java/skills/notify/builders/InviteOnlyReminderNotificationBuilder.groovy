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
package skills.notify.builders

import groovy.json.JsonSlurper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Component
import org.thymeleaf.context.Context
import org.thymeleaf.spring6.SpringTemplateEngine
import skills.storage.model.Notification

@Component
class InviteOnlyReminderNotificationBuilder implements NotificationEmailBuilder {

    private static final String INVITE_REMINDER_TEMPLATE = "project_invitation_reminder.html"

    JsonSlurper jsonSlurper = new JsonSlurper()

    @Autowired
    SpringTemplateEngine thymeleafTemplateEngine;

    @Override
    String getId() {
        Notification.Type.InviteOnlyReminder.toString()
    }

    @Override
    Res build(Notification notification, Formatting formatParams) {
        def parsed = jsonSlurper.parseText(notification.encodedParams)
        Context context = buildThymeleafContext(parsed, formatParams)
        try {
            String htmlBody = thymeleafTemplateEngine.process(INVITE_REMINDER_TEMPLATE, context)
            String plainText = buildPlainText(parsed, formatParams)
            return new Res(
                    subject: "SkillTree Project Invitation Reminder",
                    html: htmlBody,
                    plainText: plainText,
                    userIdsAreEmailAdresses: true,
            )
        } catch(Exception e) {
            e.printStackTrace()
            throw e
        }
    }

    private Context buildThymeleafContext(Object parsed, Formatting formatting) {
        Context templateContext = new Context()
        templateContext.setVariable("projectId", parsed.projectId)
        templateContext.setVariable("publicUrl", parsed.publicUrl)
        templateContext.setVariable("projectName", parsed.projectName)
        templateContext.setVariable("relativeTime", parsed.relativeTime)
        templateContext.setVariable("inviteCode", parsed.inviteCode)
        templateContext.setVariable("htmlHeader", formatting.htmlHeader)
        templateContext.setVariable("htmlFooter", formatting.htmlFooter)

        return templateContext
    }

    private String buildPlainText(Object parsed, Formatting formatting) {

        String pt = """
This is a friendly reminder that you have been invited to join the ${parsed.projectName} project. Please use the link below to accept the invitation. Your invitation will expire approximately ${parsed.relativeTime}.

${parsed.publicUrl}join-project/${parsed.projectId}/${parsed.inviteCode}?pn=${parsed.projectName}

Always yours,
SkillTree Bot
"""

        if (formatting.plaintextHeader) {
            pt = "${formatting.plaintextHeader}\n${pt}"
        }
        if (formatting.plaintextFooter) {
            pt = "${pt}\n${formatting.plaintextFooter}"
        }

        return pt

    }
}
