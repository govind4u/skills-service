/*
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
import moment from 'moment-timezone';

const dateFormatter = value => moment.utc(value).format('YYYY-MM-DD[T]HH:mm:ss[Z]');

describe('Client Display Self Report Skills Tests', () => {

  beforeEach(() => {
    Cypress.env('disabledUILoginProp', true);
    cy.createProject(1);
    cy.createSubject(1, 1)

    Cypress.Commands.add("approveRequest", (requestNum=0) => {
      cy.request('/admin/projects/proj1/approvals?limit=10&ascending=true&page=1&orderBy=userId')
          .then((response) => {
            cy.request('POST', '/admin/projects/proj1/approvals/approve', {
              skillApprovalIds: [response.body.data[requestNum].id],
            });
          });
    });

    Cypress.Commands.add("rejectRequest", (requestNum=0, rejectionMsg='Skill was rejected') => {
      cy.request('/admin/projects/proj1/approvals?limit=10&ascending=true&page=1&orderBy=userId')
          .then((response) => {
            cy.request('POST', '/admin/projects/proj1/approvals/reject', {
              skillApprovalIds: [response.body.data[requestNum].id],
              rejectionMessage: rejectionMsg,
            });
          });
    });

    Cypress.Commands.add("submitForApproval", (skillNum='1') => {
      // cy.request('POST', `/api/projects/proj1/skills/${skillId}`)
      const m = moment.utc();
      cy.request('POST', `/api/projects/proj1/skills/skill${skillNum}`, {userId: Cypress.env('proxyUser'), timestamp: m.clone().subtract(5, 'day').format('x')})
    });
  })


  it('only show self-report button if enabled', () => {
    cy.createSkill(1, 1, 1, {selfReportingType : 'Approval'});
    cy.createSkill(1, 1, 2, {selfReportingType: 'HonorSystem'});
    cy.createSkill(1, 1, 3);

    cy.cdVisit('/?internalBackButton=true');
    cy.cdClickSubj(0);
    cy.get('[data-cy=toggleSkillDetails]').click()

    cy.get('[data-cy="skillProgress_index-0"] [data-cy="selfReportBtn"]').should('exist');
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="selfReportBtn"]').should('exist');
    cy.get('[data-cy="skillProgress_index-2"] [data-cy="selfReportBtn"]').should('not.exist');

    cy.cdClickSkill(0);
    cy.get('[data-cy="selfReportBtn"]').should('exist');

    cy.cdBack('Subject 1');
    cy.cdClickSkill(1);
    cy.get('[data-cy="selfReportBtn"]').should('exist');

    cy.cdBack('Subject 1');
    cy.cdClickSkill(2);
    cy.get('[data-cy="selfReportBtn"]').should('not.exist');
  });

  it('do not show report if skill is completed', () => {
    cy.createSkill(1, 1, 1, {selfReportingType: 'HonorSystem'});

    cy.cdVisit('/');
    const m = moment.utc('2020-09-12 11', 'YYYY-MM-DD HH');
    cy.request('POST', `/api/projects/proj1/skills/skill1`, {userId: Cypress.env('proxyUser'), timestamp: m.clone().add(1, 'day').format('x')})
    cy.request('POST', `/api/projects/proj1/skills/skill1`, {userId: Cypress.env('proxyUser'), timestamp: m.clone().add(2, 'day').format('x')})

    cy.cdClickSubj(0);
    cy.cdClickSkill(0);

    cy.get('[data-cy="selfReportBtn"]').should('not.exist');
  })

  it('do not show report if skill has uncompleted dependencies', () => {
    cy.createSkill(1, 1, 1, {selfReportingType : 'HonorSystem'});
    cy.createSkill(1, 1, 2, {selfReportingType: 'HonorSystem'});

    cy.request('POST', `/admin/projects/proj1/skills/skill1/dependency/skill2`)
    cy.cdVisit('/?internalBackButton=true');
    cy.cdClickSubj(0);
    cy.cdClickSkill(0);

    cy.get('[data-cy="selfReportBtn"]').should('not.exist');

    const m = moment.utc('2020-09-12 11', 'YYYY-MM-DD HH');
    cy.request('POST', `/api/projects/proj1/skills/skill2`, {userId: Cypress.env('proxyUser'), timestamp: m.clone().add(1, 'day').format('x')})
    cy.request('POST', `/api/projects/proj1/skills/skill2`, {userId: Cypress.env('proxyUser'), timestamp: m.clone().add(2, 'day').format('x')})

    cy.cdBack('Subject 1')
    cy.cdClickSkill(0);
    cy.get('[data-cy="selfReportBtn"]').should('be.enabled');
  })


  it('self report honor skill', () => {
    cy.createSkill(1, 1, 1, { selfReportingType : 'HonorSystem', pointIncrement: 50,  pointIncrementInterval: 0 });
    cy.cdVisit('/');
    cy.cdClickSubj(0);
    cy.cdClickSkill(0);

    cy.get('[data-cy="selfReportBtn"]').click();
    cy.get('[data-cy="selfReportSkillMsg"]').contains('This skill can be submitted under the Honor System and 50 points will be awarded right away')
    cy.get('[data-cy="selfReportSubmitBtn"]').click();

    cy.get('[data-cy="selfReportAlert"]').contains("You just earned 50 points!")
    cy.get('[data-cy="overallPointsEarnedCard"] [data-cy="progressInfoCardTitle"]').contains('50');
    cy.get('[data-cy="pointsAchievedTodayCard"] [data-cy="progressInfoCardTitle"]').contains('50');
    cy.get('[data-cy="pointsPerOccurrenceCard"] [data-cy="progressInfoCardTitle"]').contains('50');
    cy.get('[data-cy="skillProgress-ptsOverProgressBard"]').contains('50 / 100 Points')

    cy.matchSnapshotImageForElement('[data-cy="skillProgressBar"]', 'Halfway_Progress');

    cy.get('[data-cy="selfReportBtn"]').click();
    cy.get('[data-cy="selfReportSkillMsg"]').contains('This skill can be submitted under the Honor System and 50 points will be awarded right away')
    cy.get('[data-cy="selfReportSubmitBtn"]').click();

    cy.get('[data-cy="selfReportAlert"]').contains("You just earned 50 points and completed the skill!")
    cy.get('[data-cy="selfReportBtn"]').should('be.disabled');
    cy.get('[data-cy="overallPointsEarnedCard"] [data-cy="progressInfoCardTitle"]').contains('100');
    cy.get('[data-cy="pointsAchievedTodayCard"] [data-cy="progressInfoCardTitle"]').contains('100');
    cy.get('[data-cy="pointsPerOccurrenceCard"] [data-cy="progressInfoCardTitle"]').contains('50');
    cy.get('[data-cy="skillProgress-ptsOverProgressBard"]').contains('100 / 100 Points')

    cy.matchSnapshotImageForElement('[data-cy="skillProgressBar"]', 'Full_Progress');

    cy.contains('Achieved on ')
  });

  it('self report honor skill from subject page', () => {
    cy.createSkill(1, 1, 1, {selfReportingType : 'Approval', pointIncrement: 50,  pointIncrementInterval: 0 });
    cy.createSkill(1, 1, 2, {selfReportingType: 'HonorSystem', pointIncrement: 50,  pointIncrementInterval: 0 });
    cy.createSkill(1, 1, 3);

    cy.cdVisit('/');
    cy.cdClickSubj(0);

    cy.get('[data-cy=toggleSkillDetails]').click()

    cy.get('[data-cy="skillProgress_index-1"] [data-cy="selfReportBtn"]').click();
    cy.get('[data-cy="selfReportSkillMsg"]').contains('This skill can be submitted under the Honor System and 50 points will be awarded right away')
    cy.get('[data-cy="selfReportSubmitBtn"]').click();

    cy.get('[data-cy="skillProgress_index-1"] [data-cy="selfReportAlert"]').contains("You just earned 50 points!")
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="overallPointsEarnedCard"] [data-cy="progressInfoCardTitle"]').contains('50');
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="pointsAchievedTodayCard"] [data-cy="progressInfoCardTitle"]').contains('50');
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="pointsPerOccurrenceCard"] [data-cy="progressInfoCardTitle"]').contains('50');
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="skillProgress-ptsOverProgressBard"]').contains('50 / 100 Points')

    cy.matchSnapshotImageForElement('[data-cy="skillProgress_index-1"] [data-cy="skillProgressBar"]', 'Halfway_Progress_On_Subj_Page');

    cy.get('[data-cy="skillProgress_index-1"] [data-cy="selfReportBtn"]').click();
    cy.get('[data-cy="selfReportSkillMsg"]').contains('This skill can be submitted under the Honor System and 50 points will be awarded right away')
    cy.get('[data-cy="selfReportSubmitBtn"]').click();

    cy.get('[data-cy="skillProgress_index-1"] [data-cy="selfReportAlert"]').contains("You just earned 50 points and completed the skill!")
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="selfReportBtn"]').should('be.disabled');
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="overallPointsEarnedCard"] [data-cy="progressInfoCardTitle"]').contains('100');
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="pointsAchievedTodayCard"] [data-cy="progressInfoCardTitle"]').contains('100');
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="pointsPerOccurrenceCard"] [data-cy="progressInfoCardTitle"]').contains('50');
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="skillProgress-ptsOverProgressBard"]').contains('100 / 100 Points')

    cy.matchSnapshotImageForElement('[data-cy="skillProgress_index-1"] [data-cy="skillProgressBar"]', 'Full_Progress_On_Subj_Page');

    cy.get('[data-cy="skillProgress_index-1"]').contains('Achieved on ')
  });

  it('self report approval-required skill - skill gets approved', () => {
    cy.createSkill(1, 1, 1, {selfReportingType : 'Approval', pointIncrement: 50,  pointIncrementInterval: 0 });
    cy.cdVisit('/');
    cy.cdClickSubj(0);
    cy.cdClickSkill(0);

    cy.get('[data-cy="selfReportBtn"]').click();
    cy.get('[data-cy="selfReportSkillMsg"]').contains('This skill requires approval. Submit with an optional message and it will enter an approval queue.')
    cy.get('[data-cy="selfReportSubmitBtn"]').click();

    cy.get('[data-cy="selfReportAlert"]').contains("This skill requires approval from a project administrator. Now let's play the waiting game! ")
    cy.get('[data-cy="selfReportBtn"]').should('be.disabled');
    cy.get('[data-cy="overallPointsEarnedCard"] [data-cy="progressInfoCardTitle"]').contains('0');
    cy.get('[data-cy="pendingApprovalStatus"]').contains('Pending Approval')
    cy.get('[data-cy="pendingApprovalStatus"]').contains('Submitted a few seconds ago')

    // refresh the page and validate that submit button is disabled and approval status is still displayed
    cy.cdVisit('/');
    cy.cdClickSubj(0);
    cy.cdClickSkill(0);
    cy.get('[data-cy="selfReportBtn"]').should('be.disabled');
    cy.get('[data-cy="overallPointsEarnedCard"] [data-cy="progressInfoCardTitle"]').contains('0');
    cy.get('[data-cy="pendingApprovalStatus"]').contains('Pending Approval')
    cy.get('[data-cy="pendingApprovalStatus"]').contains('Submitted a few seconds ago')

    // approve and then visit page again
    cy.approveRequest();
    cy.cdVisit('/');
    cy.cdClickSubj(0);
    cy.cdClickSkill(0);

    cy.get('[data-cy="selfReportBtn"]').should('be.enabled');
    cy.get('[data-cy="pendingApprovalStatus"]').should('not.exist');
    cy.get('[data-cy="overallPointsEarnedCard"] [data-cy="progressInfoCardTitle"]').contains('50');
    cy.get('[data-cy="pointsAchievedTodayCard"] [data-cy="progressInfoCardTitle"]').contains('50');
    cy.get('[data-cy="pointsPerOccurrenceCard"] [data-cy="progressInfoCardTitle"]').contains('50');
    cy.get('[data-cy="skillProgress-ptsOverProgressBard"]').contains('50 / 100 Points')
  });

  it('self report - skill was submitted for approval', () => {
    cy.createSkill(1, 1, 1, {selfReportingType : 'Approval'});
    cy.submitForApproval()


    cy.cdVisit('/');
    cy.cdClickSubj(0);
    cy.cdClickSkill(0);

    cy.get('[data-cy="selfReportBtn"]').should('be.disabled');
    cy.get('[data-cy="overallPointsEarnedCard"] [data-cy="progressInfoCardTitle"]').contains('0');
    cy.get('[data-cy="pendingApprovalStatus"]').contains('Pending Approval')
    cy.get('[data-cy="pendingApprovalStatus"]').contains('Submitted 5 days ago')
  });

  it('self report - skill was submitted for approval - on subject page', () => {
    cy.createSkill(1, 1, 1, {selfReportingType : 'Approval'});
    cy.createSkill(1, 1, 2, {selfReportingType: 'HonorSystem'});
    cy.submitForApproval()


    cy.cdVisit('/');
    cy.cdClickSubj(0);
    cy.get('[data-cy=toggleSkillDetails]').click()

    cy.get('[data-cy="skillProgress_index-0"] [data-cy="selfReportBtn"]').should('be.disabled');
    cy.get('[data-cy="skillProgress_index-0"] [data-cy="overallPointsEarnedCard"] [data-cy="progressInfoCardTitle"]').contains('0');
    cy.get('[data-cy="skillProgress_index-0"] [data-cy="pendingApprovalStatus"]').contains('Pending Approval')
    cy.get('[data-cy="skillProgress_index-0"] [data-cy="pendingApprovalStatus"]').contains('Submitted 5 days ago')
  });

  it('self report - skill was rejected', () => {
    cy.createSkill(1, 1, 1, {selfReportingType : 'Approval'});
    cy.submitForApproval();
    cy.rejectRequest();

    cy.cdVisit('/');
    cy.cdClickSubj(0);
    cy.cdClickSkill(0);

    cy.get('[data-cy="selfReportBtn"]').should('be.enabled');
    cy.get('[data-cy="overallPointsEarnedCard"] [data-cy="progressInfoCardTitle"]').contains('0');
    cy.get('[data-cy="approvalRejectedStatus"]').contains('Approval Rejected')
    cy.get('[data-cy="approvalRejectedStatus"]').contains('Rejected a few seconds ago')
    cy.get('[data-cy="selfReportRejectedAlert"]').contains('The reason is: "Skill was rejected"')
  });


  it('self report - skill was rejected - on subject page', () => {
    cy.createSkill(1, 1, 1, {selfReportingType : 'HonorSystem', pointIncrement: 200,  pointIncrementInterval: 0 });
    cy.createSkill(1, 1, 2, {selfReportingType: 'Approval', pointIncrement: 200,  pointIncrementInterval: 0 });
    cy.createSkill(1, 1, 3);
    cy.submitForApproval(2);
    cy.rejectRequest();

    cy.cdVisit('/');
    cy.cdClickSubj(0);
    cy.get('[data-cy=toggleSkillDetails]').click()

    cy.get('[data-cy="skillProgress_index-1"] [data-cy="selfReportBtn"]').should('be.enabled');
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="overallPointsEarnedCard"] [data-cy="progressInfoCardTitle"]').contains('0');
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="approvalRejectedStatus"]').contains('Approval Rejected')
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="approvalRejectedStatus"]').contains('Rejected a few seconds ago')
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="selfReportRejectedAlert"]').contains('The reason is: "Skill was rejected"')
  });

  it('self report - resubmit rejected skill', () => {
    cy.createSkill(1, 1, 1, {selfReportingType : 'Approval'});
    cy.submitForApproval();
    cy.rejectRequest();

    cy.cdVisit('/');
    cy.cdClickSubj(0);
    cy.cdClickSkill(0);

    cy.get('[data-cy="approvalRejectedStatus"]').contains('Approval Rejected')
    cy.get('[data-cy="selfReportBtn"]').click()

    cy.get('[data-cy="selfReportSkillMsg"]').contains('This skill requires approval. Submit with an optional message and it will enter an approval queue.')
    cy.get('[data-cy="selfReportSubmitBtn"]').click();

    cy.get('[data-cy="selfReportAlert"]').contains("This skill requires approval from a project administrator. Now let's play the waiting game!")
    cy.get('[data-cy="selfReportBtn"]').should('be.disabled');
    cy.get('[data-cy="overallPointsEarnedCard"] [data-cy="progressInfoCardTitle"]').contains('0');
    cy.get('[data-cy="pendingApprovalStatus"]').contains('Pending Approval')
    cy.get('[data-cy="pendingApprovalStatus"]').contains('Submitted a few seconds ago')

    cy.cdVisit('/');
    cy.cdClickSubj(0);
    cy.cdClickSkill(0);
    cy.get('[data-cy="selfReportAlert"]').should('not.exist')
    cy.get('[data-cy="selfReportBtn"]').should('be.disabled');
    cy.get('[data-cy="overallPointsEarnedCard"] [data-cy="progressInfoCardTitle"]').contains('0');
    cy.get('[data-cy="pendingApprovalStatus"]').contains('Pending Approval')
    cy.get('[data-cy="pendingApprovalStatus"]').contains('Submitted a few seconds ago')
  });

  it('self report - resubmit rejected skill - on subject page', () => {
    cy.createSkill(1, 1, 1, {selfReportingType : 'HonorSystem'});
    cy.createSkill(1, 1, 2, {selfReportingType: 'Approval'});
    cy.createSkill(1, 1, 3);
    cy.submitForApproval(2);
    cy.rejectRequest();

    cy.cdVisit('/');
    cy.cdClickSubj(0);
    cy.get('[data-cy=toggleSkillDetails]').click()

    cy.get('[data-cy="skillProgress_index-1"] [data-cy="approvalRejectedStatus"]').contains('Approval Rejected')
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="selfReportBtn"]').click()

    cy.get('[data-cy="selfReportSkillMsg"]').contains('This skill requires approval. Submit with an optional message and it will enter an approval queue.')
    cy.get('[data-cy="selfReportSubmitBtn"]').click();

    cy.get('[data-cy="skillProgress_index-1"] [data-cy="selfReportAlert"]').contains("This skill requires approval from a project administrator. Now let's play the waiting game! ")
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="selfReportBtn"]').should('be.disabled');
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="overallPointsEarnedCard"] [data-cy="progressInfoCardTitle"]').contains('0');
    cy.get('[data-cy="pendingApprovalStatus"]').contains('Pending Approval')
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="pendingApprovalStatus"]').contains('Submitted a few seconds ago')

    cy.cdVisit('/');
    cy.cdClickSubj(0);
    cy.get('[data-cy=toggleSkillDetails]').click()

    cy.get('[data-cy="skillProgress_index-1"] [data-cy="selfReportAlert"]').should('not.exist')
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="selfReportBtn"]').should('be.disabled');
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="overallPointsEarnedCard"] [data-cy="progressInfoCardTitle"]').contains('0');
    cy.get('[data-cy="pendingApprovalStatus"]').contains('Pending Approval')
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="pendingApprovalStatus"]').contains('Submitted a few seconds ago')
  });

  it('self report - delete rejection', () => {
    cy.createSkill(1, 1, 1, {selfReportingType : 'Approval'});
    cy.submitForApproval();
    cy.rejectRequest();

    cy.cdVisit('/');
    cy.cdClickSubj(0);
    cy.cdClickSkill(0);

    cy.get('[data-cy="approvalRejectedStatus"]').contains('Approval Rejected')

    cy.get('[data-cy="approvalRejectedStatus"]').contains('Approval Rejected')
    cy.get('[data-cy="selfReportRejectedAlert"]').contains('The reason is: "Skill was rejected"')

    cy.get('[data-cy="clearRejectionMsgBtn"]').click();
    cy.get('[data-cy="clearRejectionMsgDialog"]').contains('This action will permanently remove the rejection and its message. Are you sure?');
    cy.get('[data-cy="removeRejectionBtn"]').click()

    cy.get('[data-cy="approvalRejectedStatus"]').should('not.exist')
    cy.get('[data-cy="selfReportRejectedAlert"]').should('not.exist')
    cy.get('[data-cy="pendingApprovalStatus"]').should('not.exist');

    cy.cdVisit('/');
    cy.cdClickSubj(0);
    cy.cdClickSkill(0);

    cy.get('[data-cy="approvalRejectedStatus"]').should('not.exist')
    cy.get('[data-cy="selfReportRejectedAlert"]').should('not.exist')
    cy.get('[data-cy="pendingApprovalStatus"]').should('not.exist');
  });


  it('self report - delete rejection - subject page', () => {
    cy.createSkill(1, 1, 1, {selfReportingType : 'Approval'});
    cy.submitForApproval();
    cy.rejectRequest();

    cy.cdVisit('/');
    cy.cdClickSubj(0);
    cy.get('[data-cy=toggleSkillDetails]').click()

    cy.get('[data-cy="approvalRejectedStatus"]').contains('Approval Rejected')

    cy.get('[data-cy="approvalRejectedStatus"]').contains('Approval Rejected')
    cy.get('[data-cy="selfReportRejectedAlert"]').contains('The reason is: "Skill was rejected"')

    cy.get('[data-cy="clearRejectionMsgBtn"]').click();
    cy.get('[data-cy="clearRejectionMsgDialog"]').contains('This action will permanently remove the rejection and its message. Are you sure?');
    cy.get('[data-cy="removeRejectionBtn"]').click()

    cy.get('[data-cy="approvalRejectedStatus"]').should('not.exist')
    cy.get('[data-cy="selfReportRejectedAlert"]').should('not.exist')
    cy.get('[data-cy="pendingApprovalStatus"]').should('not.exist');

    cy.cdVisit('/');
    cy.cdClickSubj(0);
    cy.get('[data-cy=toggleSkillDetails]').click();

    cy.get('[data-cy="approvalRejectedStatus"]').should('not.exist')
    cy.get('[data-cy="selfReportRejectedAlert"]').should('not.exist')
    cy.get('[data-cy="pendingApprovalStatus"]').should('not.exist');
  });

  it('validate approval message if custom validator is configured', () => {

    cy.intercept('POST', '/api/projects/proj1/skills/skill1', (req) => {
      expect(req.body.approvalRequestedMsg).to.include('some val jabberwock')
    }).as('reportSkill');

    cy.createSkill(1, 1, 1, {selfReportingType : 'Approval'});
    cy.cdVisit('/');
    cy.cdClickSubj(0);
    cy.cdClickSkill(0);

    cy.get('[data-cy="selfReportBtn"]').click();
    cy.get('[data-cy="selfReportSkillMsg"]').contains('This skill requires approval. Submit with an optional message and it will enter an approval queue.')

    cy.get('[data-cy="selfReportMsgInput"]').type('some val');
    cy.get('[data-cy="selfReportSubmitBtn"]').should('be.enabled');
    cy.get('[data-cy="selfReportMsgInput_errMsg"]').should('not.exist');

    cy.get('[data-cy="selfReportMsgInput"]').type(' jabberwocky ok');
    cy.get('[data-cy="selfReportSubmitBtn"]').should('be.disabled');
    cy.get('[data-cy="selfReportMsgInput_errMsg"]').contains('paragraphs may not contain jabberwocky')

    cy.get('[data-cy="selfReportMsgInput"]').type('{backspace}{backspace}{backspace}');
    cy.get('[data-cy="selfReportSubmitBtn"]').should('be.disabled');
    cy.get('[data-cy="selfReportMsgInput_errMsg"]').contains('paragraphs may not contain jabberwocky')

    cy.get('[data-cy="selfReportMsgInput"]').type('{backspace}');
    cy.get('[data-cy="selfReportSubmitBtn"]').should('be.enabled');
    cy.get('[data-cy="selfReportMsgInput_errMsg"]').should('not.exist');

    cy.get('[data-cy="selfReportSubmitBtn"]').click();
    cy.wait('@reportSkill');
  });

  it('clearly indicate which skills are self reportable', () => {
    cy.createSkill(1, 1, 1, {selfReportingType : 'Approval'});
    cy.createSkill(1, 1, 2);
    cy.createSkill(1, 1, 3, {selfReportingType: 'HonorSystem'});

    cy.cdVisit('/');
    cy.cdClickSubj(0);

    cy.get('[data-cy="skillProgress_index-0"]').contains('Self Reportable');
    cy.get('[data-cy="skillProgress_index-1"]').contains('Self Reportable').should('not.exist');
    cy.get('[data-cy="skillProgress_index-2"]').contains('Self Reportable');

    cy.matchSnapshotImageForElement('[data-cy="skillProgress_index-0"]', 'Self_Reportable Label');

    cy.cdVisit('/?enableTheme=true');
    cy.cdClickSubj(0);
    cy.matchSnapshotImageForElement('[data-cy="skillProgress_index-0"]', 'Self_Reportable Label - Themed');
  });

  it('clearly indicate on the skill overview whether skill is self reportable', () => {
    cy.createSkill(1, 1, 1, {selfReportingType : 'Approval'});
    cy.createSkill(1, 1, 2);
    cy.createSkill(1, 1, 3, {selfReportingType: 'HonorSystem'});

    cy.cdVisit('/');
    cy.cdClickSubj(0);
    cy.cdClickSkill(0);

    cy.get('[data-cy="skillProgressTitle"]').contains('Self Reportable');
    cy.matchSnapshotImageForElement('[data-cy="skillProgressTitle"]', 'Self_Reportable Label on Skill Overview');

    cy.cdBack('Subject 1');
    cy.cdClickSkill(1);

    cy.get('[data-cy="skillProgressTitle"]').contains('Self Reportable').should('not.exist');

    cy.cdVisit('/?enableTheme=true');
    cy.cdClickSubj(0);
    cy.cdClickSkill(0);
    cy.matchSnapshotImageForElement('[data-cy="skillProgressTitle"]', 'Self_Reportable Label on Skill Overview - Themed');
  });

  it('attempt to report skill with insufficient project points', () => {
    cy.createSkill(1, 1, 1, {selfReportingType : 'Approval', pointIncrement: 10});
    cy.createSkill(1, 1, 2, {selfReportingType : 'HonorSystem', pointIncrement: 10});

    cy.cdVisit('/');
    cy.cdClickSubj(0);
    cy.cdClickSkill(0);

    cy.get('[data-cy="selfReportBtn"]').click();
    cy.get('[data-cy="selfReportSubmitBtn"]').click();
    cy.get('[data-cy="selfReportError"]').contains('Insufficient project points, skill achievement is disallowed');


    cy.cdVisit('/');
    cy.cdClickSubj(0);
    cy.cdClickSkill(1);

    cy.get('[data-cy="selfReportBtn"]').click();
    cy.get('[data-cy="selfReportSubmitBtn"]').click();
    cy.get('[data-cy="selfReportError"]').contains('Insufficient project points, skill achievement is disallowed');
  });

  it('attempt to report skill with insufficient subject points', () => {
    cy.createSkill(1, 1, 1, {selfReportingType : 'Approval', pointIncrement: 10});
    cy.createSkill(1, 1, 2, {selfReportingType : 'HonorSystem', pointIncrement: 10});

    cy.createSubject(1, 2)
    cy.createSkill(1, 2, 1, {selfReportingType : 'HonorSystem', pointIncrement: 200});

    cy.cdVisit('/');
    cy.cdClickSubj(0);
    cy.cdClickSkill(0);

    cy.get('[data-cy="selfReportBtn"]').click();
    cy.get('[data-cy="selfReportSubmitBtn"]').click();
    cy.get('[data-cy="selfReportError"]').contains('Insufficient Subject points, skill achievement is disallowed');

    cy.cdVisit('/');
    cy.cdClickSubj(0);
    cy.cdClickSkill(1);

    cy.get('[data-cy="selfReportBtn"]').click();
    cy.get('[data-cy="selfReportSubmitBtn"]').click();
    cy.get('[data-cy="selfReportError"]').contains('Insufficient Subject points, skill achievement is disallowed');
  });

  it('self report honor system updates overall progress and points', () => {
    cy.createSkill(1, 1, 1, {selfReportingType : 'Approval', pointIncrement: 50,  pointIncrementInterval: 0 });
    cy.createSkill(1, 1, 2, {selfReportingType: 'HonorSystem', pointIncrement: 50,  pointIncrementInterval: 0 });
    cy.createSkill(1, 1, 3);

    cy.cdVisit('/');
    cy.cdClickSubj(0);

    cy.get('[data-cy=toggleSkillDetails]').click()

    cy.get('.user-skills-overview .circle-number').eq(0).contains('0');
    cy.get('.user-skills-overview .circle-number').eq(0).contains('out of');
    cy.get('.user-skills-overview .circle-number').eq(0).contains('400');
    cy.get('.progress-circle-wrapper').eq(0).contains('0 Points earned Today');
    cy.get('.user-skills-overview .circle-number').eq(1).contains('0');
    cy.get('.user-skills-overview .circle-number').eq(1).contains('out of');
    cy.get('.user-skills-overview .circle-number').eq(1).contains('40');
    cy.get('.progress-circle-wrapper').eq(1).contains('0 Points earned Today');
    cy.get('.progress-circle-wrapper').eq(1).contains('40 Points to Level 1');

    cy.get('[data-cy="skillProgress_index-1"] [data-cy="selfReportBtn"]').click();
    cy.get('[data-cy="selfReportSkillMsg"]').contains('This skill can be submitted under the Honor System and 50 points will be awarded right away')
    cy.get('[data-cy="selfReportSubmitBtn"]').click();

    cy.get('[data-cy="skillProgress_index-1"] [data-cy="selfReportAlert"]').contains("You just earned 50 points!")
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="overallPointsEarnedCard"] [data-cy="progressInfoCardTitle"]').contains('50');
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="pointsAchievedTodayCard"] [data-cy="progressInfoCardTitle"]').contains('50');
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="pointsPerOccurrenceCard"] [data-cy="progressInfoCardTitle"]').contains('50');
    cy.get('[data-cy="skillProgress_index-1"] [data-cy="skillProgress-ptsOverProgressBard"]').contains('50 / 100 Points')

    cy.get('.user-skills-overview .circle-number').eq(0).contains('50');
    cy.get('.user-skills-overview .circle-number').eq(0).contains('out of');
    cy.get('.user-skills-overview .circle-number').eq(0).contains('400');
    cy.get('.progress-circle-wrapper').eq(0).contains('50 Points earned Today');
    cy.get('.user-skills-overview .circle-number').eq(1).contains('10');
    cy.get('.user-skills-overview .circle-number').eq(1).contains('out of');
    cy.get('.user-skills-overview .circle-number').eq(1).contains('60');
    cy.get('.progress-circle-wrapper').eq(1).contains('50 Points earned Today');
    cy.get('.progress-circle-wrapper').eq(1).contains('50 Points to Level 2');
  });
})
