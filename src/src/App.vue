<template>
  <div class="tfe-app">
    <tfe-default-layout />
  </div>
</template>

<script setup lang="ts">
  import TfeDefaultLayout from '@layouts/default/default.vue';
  import { registerGlobalListeners, removeGlobalListeners } from '@/helpers/global-listeners';
  import { onMounted, onUnmounted } from 'vue';

  onMounted(() => {
    registerGlobalListeners();
  });

  onUnmounted(() => {
    removeGlobalListeners();
  });
</script>

<style lang="scss">
  @import '@styles/reset.scss';

  .tfe-app {
    font-family: -apple-system, BlinkMacSystemFont, 'San Francisco', Helvetica, Arial, sans-serif;
    font-weight: 300;
  }
</style>
