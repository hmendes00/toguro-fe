<template>
  <n-avatar round v-if="src" :src="src" :size="size"></n-avatar>
  <n-avatar round :size="size" v-else>{{ GetLettersForAvatar(textFallback) }}</n-avatar>
</template>

<style lang="scss" scoped>
  @import '@styles/variables.scss';
  .n-avatar {
    --n-color: #{$secondary} !important;
    cursor: pointer;
  }
</style>

<script setup lang="ts">
  import { GetLettersForAvatar } from '@/helpers/text-manipulation';
  import { NAvatar } from 'naive-ui';
  import { ref, PropType } from 'vue';

  const url = ref('');
  defineProps({
    size: {
      type: [String, Number] as PropType<'small' | 'medium' | 'large' | number>,
      default: 'large'
    },
    src: {
      type: String
    },
    textFallback: {
      type: String,
      default: ''
    }
  });
</script>
