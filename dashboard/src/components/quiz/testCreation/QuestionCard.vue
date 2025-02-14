/*
Copyright 2024 SkillTree

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
<script setup>
import { computed, ref } from 'vue'

import MarkdownText from '@/common-components/utilities/markdown/MarkdownText.vue';
import { useQuizConfig } from "@/stores/UseQuizConfig.js";
import QuestionType from '@/skills-display/components/quiz/QuestionType.js';
import RemovalValidation from '@/components/utils/modal/RemovalValidation.vue';
import SelectCorrectAnswer from '@/components/quiz/testCreation/SelectCorrectAnswer.vue';

const quizConfig = useQuizConfig()

const props = defineProps({
  quizType: String,
  question: Object,
  questionNum: Number,
  showDragAndDropControls: Boolean
})

const emit = defineEmits(['editQuestion', 'deleteQuestion', 'sortChangeRequested', 'copyQuestion'])

const showDeleteDialog = ref(false)

const isSingleChoiceType = computed(() => {
  return props.question.questionType === QuestionType.SingleChoice;
})
const isTextInputType = computed(() => {
  return props.question.questionType === QuestionType.TextInput;
})
const isRatingType = computed(() => {
  return props.question.questionType === QuestionType.Rating;
})
const isDragAndDropControlsVisible = computed(() => {
  return !quizConfig.isReadOnlyQuiz && props.showDragAndDropControls;
})
const numberOfStars = computed(() => {
  return props.question.answers ? props.question.answers.length : 3;
})
const editQuestion = () => {
  emit('editQuestion', props.question)
}
const copyQuestion = () => {
  emit('copyQuestion', props.question)
}
const deleteQuestion = () => {
  emit('deleteQuestion', props.question)
}
const moveQuestion = (changeIndexBy) => {
  emit('sortChangeRequested', { question: props.question, newIndex: props.questionNum + changeIndexBy - 1 })
}

</script>

<template>
  <div class="border-1 border-300" data-cy="questionDisplayCard">
    <div class="flex flex-column md:flex-row flex-wrap gap-0 mb-3" :data-cy="`questionDisplayCard-${questionNum}`">
      <div class="flex flex-initial align-items-start">
        <div v-if="isDragAndDropControlsVisible"
             :id="`questionSortControl-${question.id}`"
             class="sort-control mr-3 border-right-1 border-bottom-1 surface-border text-color-secondary border-round"
             @click.prevent.self
             tabindex="0"
             aria-label="Questions Sort Control. Press up or down to change the order of this question."
             role="button"
             @keyup.down="moveQuestion(1)"
             @keyup.up="moveQuestion(-1)"
             data-cy="sortControlHandle">
          <i class="fas fa-arrows-alt"/>
        </div>
      </div>
      <div :class="{ 'ml-3' : !isDragAndDropControlsVisible }" class="flex-column flex-1 align-items-start px-2 py-1">
        <div class="flex flex-1">
          <markdown-text
              :text="question.question"
              :instance-id="`${question.id}`"
              data-cy="questionDisplayText"/>
        </div>
        <div v-if="!isTextInputType && !isRatingType">
          <div v-for="(a, index) in question.answers" :key="a.id" class="flex flex-row flex-wrap mt-1 pl-1">
            <div class="flex align-items-center justify-content-center pb-1" :data-cy="`answerDisplay-${index}`">
              <SelectCorrectAnswer v-model="a.isCorrect"
                                   :name="`answers[${index}].isCorrect`"
                                   :answer-number="index+1"
                                   :read-only="true"
                                   :is-radio-icon="isSingleChoiceType"
                                   font-size="1.3rem"/>
            </div>
            <div class="flex align-items-center justify-content-center ml-2 pb-1">
              <div class="answerText" :data-cy="`answer-${index}_displayText`">{{ a.answer }}</div>
            </div>
          </div>
        </div>
        <div v-if="isRatingType" class="flex">
          <Rating class="flex-initial surface-100 border-round py-3 px-4" :stars="numberOfStars" disabled :cancel="false"/>
        </div>
        <div v-if="isTextInputType" class="flex">
          <label :for="`q${questionNum}textInputPlaceholder`" hidden>Text Input Answer Placeholder:</label>
          <Textarea
              style="resize: none"
              class="flex-1"
              :id="`q${questionNum}textInputPlaceholder`"
              placeholder="Users will be required to enter text."
              disabled
              aria-hidden="true"
              data-cy="textAreaPlaceHolder"
              rows="2"/>
        </div>
      </div>
      <div v-if="!quizConfig.isReadOnlyQuiz" class="flex flex-none justify-content-center">
        <ButtonGroup class="ml-1 mt-2 mr-3">
          <SkillsButton @click="editQuestion"
                        icon="fas fa-edit"
                        label="Edit"
                        outlined
                        size="small"
                        :data-cy="`editQuestionButton_${questionNum}`"
                        :aria-label="`Edit Question Number ${questionNum}`"
                        :ref="`editQuestion_${question.id}`"
                        :id="`editQuestion_${question.id}`"
                        :track-for-focus="true"
                        title="Edit Question">
          </SkillsButton>
          <SkillsButton @click="copyQuestion"
                        icon="fas fa-copy"
                        label="Copy"
                        outlined
                        size="small"
                        :data-cy="`copyQuestionButton_${questionNum}`"
                        :aria-label="`Copy Question Number ${questionNum}`"
                        :ref="`copyQuestion_${question.id}`"
                        :id="`copyQuestion_${question.id}`"
                        :track-for-focus="true"
                        title="Copy Question">
          </SkillsButton>
          <SkillsButton @click="showDeleteDialog = true"
                        icon="text-warning fas fa-trash"
                        label="Delete"
                        outlined
                        size="small"
                        :data-cy="`deleteQuestionButton_${questionNum}`"
                        :aria-label="`delete question number ${questionNum}`"
                        :ref="`deleteQuestion_${question.id}`"
                        :id="`deleteQuestion_${question.id}`"
                        :track-for-focus="true"
                        title="Delete Question">
          </SkillsButton>
        </ButtonGroup>
      </div>

      <removal-validation
          v-if="showDeleteDialog"
          :item-name="`Question #${questionNum}`"
          item-type=""
          v-model="showDeleteDialog"
          focus-on-close-id="btn_Questions"
          @do-remove="deleteQuestion">
        <div>
          Any associated answers and metrics for this question will also be removed. Please proceed with caution.
        </div>
      </removal-validation>
    </div>
  </div>


</template>


<!--TODO: figure scss and theming-->
<!--@import "@/assets/custom";-->
<style lang="css" scoped>

.sort-control i {
  padding: 0.4rem;
  font-size: 1.2rem;
  top: 0rem;
  left: 0rem;
  border-bottom-right-radius: .25rem !important
}

.sort-control:hover, .sort-control i:hover {
  cursor: grab !important;
  color: #146c75 !important;
  font-size: 1.5rem;
}

.answerText {
  font-size: 0.9rem;
}

</style>