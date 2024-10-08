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
import { useField } from 'vee-validate'
import { computed } from 'vue'

const props = defineProps({
  name: {
    type: String,
    required: true,
  },
  label: {
    type: String,
    required: false,
  },
  autofocus: {
    type: Boolean,
    default: false,
  },
  disabled: {
    type: Boolean,
    default: false
  },
  placeholder: {
    type: String,
    default: ''
  },
})
const emit = defineEmits(['input'])

const { value, errorMessage } = useField(() => props.name);

const labelClass = computed(() => {
  return props.label ? 'text-secondary w-min-11rem max-w-11rem' : null
})

const inputClass = computed(() => {
  return props.label ? '' : 'w-full'
})

</script>
<!--v-bind="projectDisplayNameAttrs"-->
<template>
  <div class="field flex flex-column lg:flex-row gap-3">
    <div v-if="label" :class="labelClass" :id="`${name}Label`">
      <label :for="name">
        {{ label }}
      </label>
    </div>
    <div :class="inputClass">
      <InputText v-model="value"
                 :data-cy="`${name}TextInput`"
                 :id="name"
                 :inputId="name"
                 type="text"
                 @input="emit('input', [name, $event.target.value])"
                 class="w-full"
                 :placeholder="placeholder"
                 :class="{ 'p-invalid': errorMessage }"
                 :aria-invalid="!!errorMessage"
                 :aria-errormessage="`${name}Error`"
                 :aria-describedby="`${name}Error`"
                 :aria-labelledby="`${name}Label`" />
      <small role="alert" class="p-error" :id="`${name}Error`" :data-cy="`${name}Error`" v-if="errorMessage">{{ errorMessage || '&nbsp;' }}</small>
    </div>
  </div>
</template>

<style scoped>

</style>