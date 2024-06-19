/*
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
import { computed, ref } from 'vue'
import { defineStore } from 'pinia'

export const useEmailVerificationInfo = defineStore('useEmailVerificationInfo', () => {
    const emailVal = ref('')
    const reasonVal = ref('')
    const setEmail = (newEmail) => {
        emailVal.value = newEmail
    }
    const email = computed(() => emailVal.value)

    const setReason = (newReason) => {
        reasonVal.value = newReason
    }
    const reason = computed(() => reasonVal.value)

    return {
        email,
        setEmail,
        reason,
        setReason
    }
})