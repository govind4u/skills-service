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
package skills.services

import groovy.util.logging.Slf4j
import org.apache.poi.ss.usermodel.*
import org.apache.poi.ss.util.CellRangeAddress
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.data.domain.PageRequest
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import skills.controller.result.model.ProjectUser
import skills.controller.result.model.UserProgressExportResult
import skills.services.admin.UserCommunityService

import java.util.stream.Stream

@Service
@Slf4j
class ExcelExportService {

    @Autowired
    UserCommunityService userCommunityService

    @Autowired
    UserProgressExportResult userProgressExportResult

    @Value('${skills.config.ui.usersTableAdditionalUserTagKey:}')
    String usersTableAdditionalUserTagKey

    @Value('${skills.config.ui.usersTableAdditionalUserTagLabel:}')
    String userTagLabel

    @Value('${skills.config.ui.exportHeaderAndFooter:}')
    String exportHeaderAndFooter

    @Autowired
    private AdminUsersService adminUsersService

    @Transactional(readOnly = true)
    void exportUsersProgress(Workbook workbook, String projectId, String query, PageRequest pageRequest, int minimumPoints) {
        String projectExportHeaderAndFooter = userCommunityService.replaceProjectDescriptorVar(exportHeaderAndFooter, userCommunityService.getProjectUserCommunity(projectId))
        Sheet sheet = workbook.createSheet()
        Integer rowNum = 0
        Integer columnNumber = 0
        if (projectExportHeaderAndFooter) {
            addDataHeader(workbook, sheet, rowNum++, userTagLabel ? 8 : 7, projectExportHeaderAndFooter)
        }
        Row headerRow = sheet.createRow(rowNum++)
        headerRow.createCell(columnNumber++).setCellValue("User ID")
        headerRow.createCell(columnNumber++).setCellValue("Last Name")
        headerRow.createCell(columnNumber++).setCellValue("First Name")
        if (userTagLabel) {
            headerRow.createCell(columnNumber++).setCellValue(userTagLabel)
        }
        headerRow.createCell(columnNumber++).setCellValue("Level")
        headerRow.createCell(columnNumber++).setCellValue("Current Points")
        headerRow.createCell(columnNumber++).setCellValue("Points First Earned")
        headerRow.createCell(columnNumber++).setCellValue("Points Last Earned")

        CellStyle dateStyle = workbook.createCellStyle()
        dateStyle.setDataFormat((short) 14) // NOTE: 14 = "mm/dd/yyyy"

        Cell cell = null
        Stream<ProjectUser> projectUsers = adminUsersService.streamAllDistinctUsersForProject(projectId, query, pageRequest, minimumPoints)
        try {
            projectUsers.each { ProjectUser user ->
                columnNumber = 0
                Row row = sheet.createRow(rowNum++)
                row.createCell(columnNumber++).setCellValue(user.userIdForDisplay)
                row.createCell(columnNumber++).setCellValue(user.lastName ?: '')
                row.createCell(columnNumber++).setCellValue(user.firstName ?: '')
                if (userTagLabel) {
                    row.createCell(columnNumber++).setCellValue(user.userTag)
                }
                row.createCell(columnNumber++).setCellValue(user.userMaxLevel)
                row.createCell(columnNumber++).setCellValue(user.totalPoints)

                cell = row.createCell(columnNumber++)
                cell.setCellStyle(dateStyle)
                cell.setCellValue(user.firstUpdated)
                cell = row.createCell(columnNumber++)
                cell.setCellStyle(dateStyle)
                cell.setCellValue(user.lastUpdated)
            }
        } finally {
            projectUsers.close()
        }

        if (projectExportHeaderAndFooter) {
            addDataHeader(workbook, sheet, rowNum++, userTagLabel ? 8 : 7, projectExportHeaderAndFooter)
        }
    }

    private static void addDataHeader(Workbook workbook, Sheet sheet, Integer rowNum, Integer numCols, String exportHeaderAndFooter) {
        Row row = sheet.createRow(rowNum);
        Cell cell = row.createCell(0);
        cell.setCellValue(exportHeaderAndFooter)
        sheet.addMergedRegion(new CellRangeAddress(rowNum, rowNum, 0, numCols - 1))
    }
}