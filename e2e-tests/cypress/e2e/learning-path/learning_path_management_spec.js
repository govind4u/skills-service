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
describe('Learning Path Management Validation Tests', () => {

    const tableSelector = '[data-cy="learningPathTable"]';
    const headerSelector = `${tableSelector} thead tr th`;

    beforeEach(() => {
        Cypress.Commands.add('clickOnNode', (x, y) => {
            cy.contains('Legend');
            cy.wait(2000); // wait for chart
            // have to click twice to it to work...
            cy.get('#dependency-graph canvas')
                .should('be.visible')
                .click(x, y);
        });

        cy.createProject(1);
        cy.createSubject(1, 1);
        cy.createSubject(1, 2);
        cy.createSkill(1, 1, 1)
        cy.createSkill(1, 1, 2)
        cy.createSkill(1, 1, 3)
        cy.createSkill(1, 1, 4)
        cy.createSkill(1, 2, 5)
        cy.createSkill(1, 2, 6)
        cy.createSkill(1, 2, 7)
        cy.createSkill(1, 2, 8)

        cy.createBadge(1, 1);
        cy.assignSkillToBadge(1, 1, 1);
        cy.assignSkillToBadge(1, 1, 2);
        cy.createBadge(1, 1, { enabled: true });

        cy.createBadge(1, 2);
        cy.assignSkillToBadge(1, 2, 3);
        cy.assignSkillToBadge(1, 2, 4);
        cy.createBadge(1, 2, { enabled: true });
    });

    it('Create a simple learning path', () => {
        cy.visit('/administrator/projects/proj1/learning-path')

        // Add Badge1 as a prerequisite for Badge2
        cy.get('[data-cy="learningPathFromSkillSelector"]')
            .click();
        cy.get('[data-cy="skillsSelectionItem-proj1-badge1"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]')
            .click();
        cy.get('[data-cy="learningPathToSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-badge2"]').click();
        cy.get('[data-cy="addLearningPathItemBtn"]').click();

        // Add Skill5 as a prerequisite for Badge1
        cy.get('[data-cy="learningPathFromSkillSelector"]')
            .click();

        cy.get('[data-cy="learningPathFromSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-skill5Subj2"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]')
            .click();
        cy.get('[data-cy="learningPathToSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-badge1"]').click();
        cy.get('[data-cy="addLearningPathItemBtn"]').click();

        // Add Skill6 as a prerequisite for Badge2
        cy.get('[data-cy="learningPathFromSkillSelector"]')
            .click();
        cy.get('[data-cy="learningPathFromSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-skill6Subj2"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]')
            .click();
        cy.get('[data-cy="learningPathToSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-badge2"]').click();
        cy.get('[data-cy="addLearningPathItemBtn"]').click();

        // Add Skill7 as a prerequisite for Skill5
        cy.get('[data-cy="learningPathFromSkillSelector"]')
            .click();
        cy.get('[data-cy="learningPathFromSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-skill7Subj2"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]')
            .click();
        cy.get('[data-cy="learningPathToSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-skill5Subj2"]').click();
        cy.get('[data-cy="addLearningPathItemBtn"]').click();

        // Add Skill8 as a prerequisite for Badge1
        cy.get('[data-cy="learningPathFromSkillSelector"]')
            .click();
        cy.get('[data-cy="learningPathFromSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-skill8Subj2"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]')
            .click();
        cy.get('[data-cy="learningPathToSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-badge1"]').click();
        cy.get('[data-cy="addLearningPathItemBtn"]').click();

        cy.wait(1000);

        cy.get(headerSelector).contains('From').click();

        cy.validateTable(tableSelector, [
            [{
                colIndex: 0,
                value: 'Badge 1'
            }, {
                colIndex: 1,
                value: 'Badge 2'
            }],
            [{
                colIndex: 0,
                value: 'Very Great Skill 5 Subj2'
            }, {
                colIndex: 1,
                value: 'Badge 1'
            }],
            [{
                colIndex: 0,
                value: 'Very Great Skill 6 Subj2'
            }, {
                colIndex: 1,
                value: 'Badge 2'
            }],
            [{
                colIndex: 0,
                value: 'Very Great Skill 7 Subj2'
            }, {
                colIndex: 1,
                value: 'Very Great Skill 5 Subj2'
            }],
            [{
                colIndex: 0,
                value: 'Very Great Skill 8 Subj2'
            }, {
                colIndex: 1,
                value: 'Badge 1'
            }],
        ], 5, false, null, false);

    })

    it('add group\'s skill as a prerequisite', () => {
        cy.createSkillsGroup(1, 1, 15);
        cy.addSkillToGroup(1, 1, 15, 16);
        cy.addSkillToGroup(1, 1, 15, 17);

        cy.visit('/administrator/projects/proj1/learning-path');
        cy.get('[data-cy="fullDepsSkillsGraph"]').contains('No Learning Path Yet')
        cy.get('[data-cy="learningPathFromSkillSelector"]').click().type('16');
        cy.get('[data-cy="skillsSelectionItem-proj1-skill16"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]').click().type('17')
        cy.get('[data-cy="skillsSelectionItem-proj1-skill17"]').click();
        cy.get('[data-cy="addLearningPathItemBtn"]').should('be.enabled')
        cy.get('[data-cy="addLearningPathItemBtn"]').click()

        cy.validateTable(tableSelector, [
            [{
                colIndex: 0,
                value: 'Very Great Skill 16'
            }, {
                colIndex: 1,
                value: 'Very Great Skill 17'
            }],
        ], 5, false, null, false);
    });

    it('reused skills must NOT be available for prerequisites', () => {
        cy.createSkill(1, 1, 15);
        cy.reuseSkillIntoAnotherSubject(1, 15, 2);
        cy.createSkillsGroup(1, 1, 12);
        cy.reuseSkillIntoAnotherGroup(1, 15, 1, 12);

        cy.visit('/administrator/projects/proj1/learning-path');

        cy.get('[data-cy="fullDepsSkillsGraph"]').contains('No Learning Path Yet')
        cy.get('[data-cy="learningPathFromSkillSelector"]').click().type('15');
        cy.get('[data-cy="learningPathFromSkillSelector"] [data-cy="skillsSelectionItem-proj1-skill15"]')
        cy.get('[data-cy="learningPathFromSkillSelector"] [data-cy="skillsSelector-skillId"]')
            .should('have.length', 1)

        cy.get('[data-cy="learningPathFromSkillSelector"]').clear().type('1');
        cy.get('[data-cy="skillsSelectionItem-proj1-skill1"]').click();

        cy.get('[data-cy="learningPathToSkillSelector"]').click().type('15')
        cy.get('[data-cy="learningPathToSkillSelector"] [data-cy="skillsSelectionItem-proj1-skill15"]')
        cy.get('[data-cy="learningPathToSkillSelector"] [data-cy="skillsSelector-skillId"]')
            .should('have.length', 1)
    });

    it('Remove learning path item from the table', () => {
        cy.intercept('POST', '/admin/projects/proj1/badge2/prerequisite/proj1/badge1').as('badge1ToBadge2')
        cy.intercept('POST', '/admin/projects/proj1/badge1/prerequisite/proj1/skill5Subj2').as('skill1ToBadge1')
        cy.intercept('POST', '/admin/projects/proj1/badge2/prerequisite/proj1/skill6Subj2').as('skill6ToBadge2')
        cy.intercept('POST', '/admin/projects/proj1/skill5Subj2/prerequisite/proj1/skill7Subj2').as('skill7ToSkill5')
        cy.intercept('POST', '/admin/projects/proj1/badge1/prerequisite/proj1/skill8Subj2').as('skill8ToBadge1')
        cy.intercept('DELETE', '/admin/projects/proj1/badge2/prerequisite/proj1/badge1').as('removeBadge1ToBadge2')

        cy.visit('/administrator/projects/proj1/learning-path')

        // Add Badge1 as a prerequisite for Badge2
        cy.get('[data-cy="learningPathFromSkillSelector"]')
            .click();
        cy.get('[data-cy="skillsSelectionItem-proj1-badge1"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]')
            .click();
        cy.get('[data-cy="learningPathToSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-badge2"]').click();
        cy.get('[data-cy="addLearningPathItemBtn"]').click();
        cy.wait('@badge1ToBadge2')

        // Add Skill5 as a prerequisite for Badge1
        cy.get('[data-cy="learningPathFromSkillSelector"]')
            .click();

        cy.get('[data-cy="learningPathFromSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-skill5Subj2"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]')
            .click();
        cy.get('[data-cy="learningPathToSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-badge1"]').click();
        cy.get('[data-cy="addLearningPathItemBtn"]').click();
        cy.wait('@skill1ToBadge1')

        // Add Skill6 as a prerequisite for Badge2
        cy.get('[data-cy="learningPathFromSkillSelector"]')
            .click();
        cy.get('[data-cy="learningPathFromSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-skill6Subj2"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]')
            .click();
        cy.get('[data-cy="learningPathToSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-badge2"]').click();
        cy.get('[data-cy="addLearningPathItemBtn"]').click();
        cy.wait('@skill6ToBadge2')

        // Add Skill7 as a prerequisite for Skill5
        cy.get('[data-cy="learningPathFromSkillSelector"]')
            .click();
        cy.get('[data-cy="learningPathFromSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-skill7Subj2"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]')
            .click();
        cy.get('[data-cy="learningPathToSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-skill5Subj2"]').click();
        cy.get('[data-cy="addLearningPathItemBtn"]').click();
        cy.wait('@skill7ToSkill5')

        // Add Skill8 as a prerequisite for Badge1
        cy.get('[data-cy="learningPathFromSkillSelector"]')
            .click();
        cy.get('[data-cy="learningPathFromSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-skill8Subj2"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]')
            .click();
        cy.get('[data-cy="learningPathToSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-badge1"]').click();
        cy.get('[data-cy="addLearningPathItemBtn"]').click();
        cy.wait('@skill8ToBadge1')

        cy.wait(1000);
        
        cy.get(headerSelector).contains('From').click();

        cy.validateTable(tableSelector, [
            [{
                colIndex: 0,
                value: 'Badge 1'
            }, {
                colIndex: 1,
                value: 'Badge 2'
            }],
            [{
                colIndex: 0,
                value: 'Very Great Skill 5 Subj2'
            }, {
                colIndex: 1,
                value: 'Badge 1'
            }],
            [{
                colIndex: 0,
                value: 'Very Great Skill 6 Subj2'
            }, {
                colIndex: 1,
                value: 'Badge 2'
            }],
            [{
                colIndex: 0,
                value: 'Very Great Skill 7 Subj2'
            }, {
                colIndex: 1,
                value: 'Very Great Skill 5 Subj2'
            }],
            [{
                colIndex: 0,
                value: 'Very Great Skill 8 Subj2'
            }, {
                colIndex: 1,
                value: 'Badge 1'
            }],
        ], 5, false, null, false);

        // Remove the connection from Badge 1 and Badge 2
        cy.get('[data-cy="sharedSkillsTable-removeBtn"]').first().click();
        cy.get('button').contains('Remove').click();
        cy.wait('@removeBadge1ToBadge2')

        cy.validateTable(tableSelector, [
            [{
                colIndex: 0,
                value: 'Very Great Skill 5 Subj2'
            }, {
                colIndex: 1,
                value: 'Badge 1'
            }],
            [{
                colIndex: 0,
                value: 'Very Great Skill 6 Subj2'
            }, {
                colIndex: 1,
                value: 'Badge 2'
            }],
            [{
                colIndex: 0,
                value: 'Very Great Skill 7 Subj2'
            }, {
                colIndex: 1,
                value: 'Very Great Skill 5 Subj2'
            }],
            [{
                colIndex: 0,
                value: 'Very Great Skill 8 Subj2'
            }, {
                colIndex: 1,
                value: 'Badge 1'
            }],
        ], 5, false, null, false);
    })

    it('Clicking a node fills in the from selector', () => {
        cy.visit('/administrator/projects/proj1/learning-path')

        // Add Badge1 as a prerequisite for Badge2
        cy.get('[data-cy="learningPathFromSkillSelector"]')
            .click();
        cy.get('[data-cy="skillsSelectionItem-proj1-badge1"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]')
            .click();
        cy.get('[data-cy="learningPathToSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-badge2"]').click();
        cy.get('[data-cy="addLearningPathItemBtn"]').click();

        cy.clickOnNode(360, 200);
        cy.get('[data-cy="learningPathFromSkillSelector"]').contains('Badge 1');

        cy.clickOnNode(360, 300);
        cy.get('[data-cy="learningPathFromSkillSelector"]').contains('Badge 2');
    })

    it('Clicking a node clears the to selector and errors', () => {
        cy.visit('/administrator/projects/proj1/learning-path')

        // Add Badge1 as a prerequisite for Badge2
        cy.get('[data-cy="learningPathFromSkillSelector"]')
            .click();
        cy.get('[data-cy="skillsSelectionItem-proj1-badge1"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]')
            .click();
        cy.get('[data-cy="learningPathToSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-badge2"]').click();
        cy.get('[data-cy="addLearningPathItemBtn"]').click();

        cy.clickOnNode(360, 300);
        cy.get('[data-cy="learningPathFromSkillSelector"]').contains('Badge 2');

        cy.get('[data-cy="learningPathToSkillSelector"]')
            .click();
        cy.get('[data-cy="learningPathToSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-badge1"]').click();

        cy.get('[data-cy="learningPathError"]').contains('Badge 1 already exists in the learning path and adding it again will cause a circular/infinite learning path')

        cy.clickOnNode(360, 200);
        cy.get('[data-cy="learningPathFromSkillSelector"]').contains('Badge 1');
        cy.get('[data-cy="learningPathToSkillSelector"]').should('have.value', '');
        cy.get('[data-cy="learningPathError"]').should('not.exist')
    })

    it('Can remove a learning path route from the graph', () => {
        cy.visit('/administrator/projects/proj1/learning-path')

        // Add Badge1 as a prerequisite for Badge2
        cy.get('[data-cy="learningPathFromSkillSelector"]')
            .click();
        cy.get('[data-cy="skillsSelectionItem-proj1-badge1"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]')
            .click();
        cy.get('[data-cy="learningPathToSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-badge2"]').click();
        cy.get('[data-cy="addLearningPathItemBtn"]').click();

        cy.clickOnNode(340, 250);
        cy.get('button').contains('Remove').click();
        cy.get('[data-cy="fullDepsSkillsGraph"]').contains('No Learning Path Yet')
    })

    it('Changing the From skill clears the To skill', () => {
        cy.visit('/administrator/projects/proj1/learning-path')

        // Add Badge1 as a prerequisite for Badge2
        cy.get('[data-cy="learningPathFromSkillSelector"]')
            .click();
        cy.get('[data-cy="skillsSelectionItem-proj1-badge1"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-badge2"]').click();

        cy.get('[data-cy="learningPathFromSkillSelector"]').contains('Badge 1');
        cy.get('[data-cy="learningPathToSkillSelector"]').contains('Badge 2');

        cy.get('[data-cy="learningPathFromSkillSelector"]').click();
        cy.get('[data-cy="learningPathFromSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-skill5Subj2"]').first().click();

        cy.get('[data-cy="learningPathFromSkillSelector"]').contains('Very Great Skill 5 Subj2');
        cy.get('[data-cy="learningPathToSkillSelector"]').should('have.value', '');
    })

    it('Changing the From skill clears errors', () => {
        cy.visit('/administrator/projects/proj1/learning-path')

        // Add Badge1 as a prerequisite for Badge2
        cy.get('[data-cy="learningPathFromSkillSelector"]').click();
        cy.get('[data-cy="learningPathFromSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-badge1"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-badge2"]').click();
        cy.get('[data-cy="addLearningPathItemBtn"]').click();

        cy.get('[data-cy="learningPathFromSkillSelector"]').click();
        cy.get('[data-cy="learningPathFromSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-badge2"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-badge1"]').click();

        cy.get('[data-cy="addLearningPathItemBtn"]').should('be.disabled')
        cy.get('[data-cy="learningPathError"]').contains('Badge 1 already exists in the learning path and adding it again will cause a circular/infinite learning path')

        cy.get('[data-cy="learningPathFromSkillSelector"]').click();
        cy.get('[data-cy="learningPathFromSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-skill5Subj2"]').first().click();

        cy.get('[data-cy="learningPathError"]').should('not.exist')
    })

    it('Changing the To skill clears errors', () => {
        cy.visit('/administrator/projects/proj1/learning-path')

        // Add Badge1 as a prerequisite for Badge2
        cy.get('[data-cy="learningPathFromSkillSelector"]').click();
        cy.get('[data-cy="skillsSelectionItem-proj1-badge1"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-badge2"]').click();
        cy.get('[data-cy="addLearningPathItemBtn"]').click();

        cy.get('[data-cy="learningPathFromSkillSelector"]').click();
        cy.get('[data-cy="learningPathFromSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-badge2"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]').click();
        cy.get('[data-cy="learningPathToSkillSelector"]').find('[data-cy="skillsSelectionItem-proj1-badge1"]').first().click();

        cy.get('[data-cy="addLearningPathItemBtn"]').should('be.disabled')
        cy.get('[data-cy="learningPathError"]').contains('Badge 1 already exists in the learning path and adding it again will cause a circular/infinite learning path')

        cy.get('[data-cy="learningPathToSkillSelector"]').click();
        cy.get('[data-cy="skillsSelectionItem-proj1-skill5Subj2"]').click();

        cy.get('[data-cy="learningPathError"]').should('not.exist')
    })
});